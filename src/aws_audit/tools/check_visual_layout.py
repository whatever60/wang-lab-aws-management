#!/usr/bin/env python3
"""Check rendered SVG/HTML diagrams for common visual layout failures."""

import argparse
import math
import sys
from pathlib import Path
from typing import Any, Optional

from playwright.sync_api import sync_playwright


EDGE_SELECTOR = ".edge, .principal-edge, .bucket-tag-edge, .guardrail-edge, .service-edge"
NODE_OVERLAP_AREA_LIMIT = 16
TEXT_TOLERANCE = 2
EDGE_SAMPLE_STEP = 4
EDGE_OCCLUSION_LIMIT = 0.5
NODE_EDGE_PADDING = 2
ENDPOINT_CLEARANCE = 12
EDGE_CROSSING_LIMIT = 0
NODE_DUPLICATE_LIMIT = 0


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Render an HTML/SVG diagram and measure visual overlap."
    )
    parser.add_argument("html", type=Path, help="HTML file to render")
    parser.add_argument(
        "--screenshot",
        type=Path,
        default=Path("/tmp/visual_layout_check.png"),
        help="Path for the rendered screenshot",
    )
    parser.add_argument("--width", type=int, default=1480, help="Viewport width")
    parser.add_argument("--height", type=int, default=930, help="Viewport height")
    return parser.parse_args()


def intersection_area(first: dict[str, Any], second: dict[str, Any]) -> float:
    """Return the area shared by two viewport rectangles."""
    width = max(
        0,
        min(first["x"] + first["width"], second["x"] + second["width"])
        - max(first["x"], second["x"]),
    )
    height = max(
        0,
        min(first["y"] + first["height"], second["y"] + second["height"])
        - max(first["y"], second["y"]),
    )
    return width * height


def rect_area(rect: dict[str, Any]) -> float:
    """Return the area of a viewport rectangle."""
    return rect["width"] * rect["height"]


def point_inside_rect(
    point: dict[str, float], rect: dict[str, Any], padding: float
) -> bool:
    """Return whether a point is inside a rectangle expanded by padding."""
    return (
        rect["x"] - padding
        <= point["x"]
        <= rect["x"] + rect["width"] + padding
        and rect["y"] - padding
        <= point["y"]
        <= rect["y"] + rect["height"] + padding
    )


def distance_to_rect(point: dict[str, float], rect: dict[str, Any]) -> float:
    """Return the shortest distance from a point to a rectangle."""
    dx = max(rect["x"] - point["x"], 0, point["x"] - (rect["x"] + rect["width"]))
    dy = max(rect["y"] - point["y"], 0, point["y"] - (rect["y"] + rect["height"]))
    return math.hypot(dx, dy)


def nearest_node_index(point: dict[str, float], nodes: list[dict[str, Any]]) -> int:
    """Return the index of the node nearest to a point."""
    distances = [distance_to_rect(point, node) for node in nodes]
    return distances.index(min(distances))


def segment_length(first: dict[str, float], second: dict[str, float]) -> float:
    """Return the length of a segment between two points."""
    return math.hypot(first["x"] - second["x"], first["y"] - second["y"])


def segment_midpoint(first: dict[str, float], second: dict[str, float]) -> dict[str, float]:
    """Return the midpoint of a segment between two points."""
    return {"x": (first["x"] + second["x"]) / 2, "y": (first["y"] + second["y"]) / 2}


def near_intended_endpoint(
    edge: dict[str, Any],
    midpoint: dict[str, float],
    source_index: int,
    target_index: int,
    node_index: int,
) -> bool:
    """Return whether a segment is at an intentional source/target contact."""
    if node_index == source_index:
        return point_distance(midpoint, edge["points"][0]) <= ENDPOINT_CLEARANCE
    if node_index == target_index:
        return point_distance(midpoint, edge["points"][-1]) <= ENDPOINT_CLEARANCE
    return False


def segment_intersection(
    first_start: dict[str, float],
    first_end: dict[str, float],
    second_start: dict[str, float],
    second_end: dict[str, float],
) -> Optional[dict[str, float]]:
    """Return the intersection point for two segments, if one exists."""
    x1 = first_start["x"]
    y1 = first_start["y"]
    x2 = first_end["x"]
    y2 = first_end["y"]
    x3 = second_start["x"]
    y3 = second_start["y"]
    x4 = second_end["x"]
    y4 = second_end["y"]
    denominator = (x1 - x2) * (y3 - y4) - (y1 - y2) * (x3 - x4)
    if abs(denominator) < 0.000001:
        return None
    px = (
        (x1 * y2 - y1 * x2) * (x3 - x4)
        - (x1 - x2) * (x3 * y4 - y3 * x4)
    ) / denominator
    py = (
        (x1 * y2 - y1 * x2) * (y3 - y4)
        - (y1 - y2) * (x3 * y4 - y3 * x4)
    ) / denominator
    first_min_x = min(x1, x2) - 0.1
    first_max_x = max(x1, x2) + 0.1
    first_min_y = min(y1, y2) - 0.1
    first_max_y = max(y1, y2) + 0.1
    second_min_x = min(x3, x4) - 0.1
    second_max_x = max(x3, x4) + 0.1
    second_min_y = min(y3, y4) - 0.1
    second_max_y = max(y3, y4) + 0.1
    if (
        first_min_x <= px <= first_max_x
        and first_min_y <= py <= first_max_y
        and second_min_x <= px <= second_max_x
        and second_min_y <= py <= second_max_y
    ):
        return {"x": px, "y": py}
    return None


def point_distance(first: dict[str, float], second: dict[str, float]) -> float:
    """Return the distance between two points."""
    return math.hypot(first["x"] - second["x"], first["y"] - second["y"])


def render_page(
    html_path: Path, screenshot_path: Path, width: int, height: int
) -> dict[str, Any]:
    """Render an HTML file and return visual geometry from the browser."""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(
            viewport={"width": width, "height": height}, device_scale_factor=1
        )
        page.goto(html_path.resolve().as_uri())
        page.screenshot(path=str(screenshot_path), full_page=True)
        geometry = page.evaluate(
            """
            ({ edgeSelector, sampleStep, textTolerance }) => {
              const svg = document.querySelector("svg");
              const matrix = svg.getScreenCTM();
              const toViewport = (point) => {
                const screenPoint = point.matrixTransform(matrix);
                return { x: screenPoint.x, y: screenPoint.y };
              };
              const nodes = Array.from(document.querySelectorAll(".node")).map((node, index) => {
                const box = node.getBoundingClientRect();
                return {
                  index,
                  text: node.textContent.trim().replace(/\\s+/g, " "),
                  x: box.x,
                  y: box.y,
                  width: box.width,
                  height: box.height
                };
              });
              const textSpills = Array.from(document.querySelectorAll(".node")).flatMap((node) => {
                const rect = node.querySelector("rect").getBBox();
                const texts = Array.from(node.querySelectorAll("text"));
                return texts.map((text) => {
                  const box = text.getBBox();
                  return {
                    node: node.textContent.trim().replace(/\\s+/g, " "),
                    text: text.textContent.trim(),
                    left: box.x < rect.x + textTolerance,
                    right: box.x + box.width > rect.x + rect.width - textTolerance,
                    top: box.y < rect.y + textTolerance,
                    bottom: box.y + box.height > rect.y + rect.height - 1
                  };
                }).filter((item) => item.left || item.right || item.top || item.bottom);
              });
              const edges = Array.from(document.querySelectorAll(edgeSelector)).map((edge, index) => {
                const length = edge.getTotalLength();
                const points = [];
                for (let distance = 0; distance < length; distance += sampleStep) {
                  points.push({ ...toViewport(edge.getPointAtLength(distance)), distance });
                }
                points.push({ ...toViewport(edge.getPointAtLength(length)), distance: length });
                return {
                  index,
                  label: edge.dataset.label || `edge ${index}`,
                  crossingOk: edge.dataset.crossingOk === "true",
                  className: edge.getAttribute("class"),
                  length,
                  points
                };
              });
              return { nodes, textSpills, edges };
            }
            """,
            {
                "edgeSelector": EDGE_SELECTOR,
                "sampleStep": EDGE_SAMPLE_STEP,
                "textTolerance": TEXT_TOLERANCE,
            },
        )
        browser.close()
    return geometry


def find_node_overlaps(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return node pairs with meaningful rendered bounding-box overlap."""
    overlaps = []
    for first_index, first in enumerate(nodes):
        for second in nodes[first_index + 1 :]:
            area = intersection_area(first, second)
            if area > NODE_OVERLAP_AREA_LIMIT:
                overlaps.append(
                    {
                        "first": first["text"],
                        "second": second["text"],
                        "area": round(area, 1),
                        "ratio": round(area / min(rect_area(first), rect_area(second)), 4),
                    }
                )
    return overlaps


def find_duplicate_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return node labels that appear more than once."""
    labels = [node["text"] for node in nodes]
    duplicates = []
    for label in sorted(set(labels)):
        count = labels.count(label)
        if count > 1:
            duplicates.append({"label": label, "count": count})
    return duplicates


def find_edge_occlusions(
    edges: list[dict[str, Any]], nodes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return edges that overlap node bodies or node borders."""
    occlusions = []
    for edge in edges:
        points = edge["points"]
        source_index = nearest_node_index(points[0], nodes)
        target_index = nearest_node_index(points[-1], nodes)
        occluded_length = 0.0
        occluding_nodes = set()
        for point_index, point in enumerate(points[:-1]):
            next_point = points[point_index + 1]
            midpoint = segment_midpoint(point, next_point)
            length = segment_length(point, next_point)
            for node in nodes:
                if near_intended_endpoint(
                    edge, midpoint, source_index, target_index, node["index"]
                ):
                    continue
                if point_inside_rect(midpoint, node, NODE_EDGE_PADDING):
                    occluded_length += length
                    occluding_nodes.add(node["text"])
                    break
        if occluded_length > EDGE_OCCLUSION_LIMIT:
            occlusions.append(
                {
                    "edge": edge["index"],
                    "class": edge["className"],
                    "source": nodes[source_index]["text"],
                    "target": nodes[target_index]["text"],
                    "occluded_px": round(occluded_length, 1),
                    "nodes": sorted(occluding_nodes),
                }
            )
    return occlusions


def point_inside_any_node(point: dict[str, float], nodes: list[dict[str, Any]]) -> bool:
    """Return whether a point falls inside any node rectangle."""
    return any(point_inside_rect(point, node, 6) for node in nodes)


def crossing_already_counted(
    point: dict[str, float], crossings: list[dict[str, Any]]
) -> bool:
    """Return whether a crossing point is already represented nearby."""
    return any(point_distance(point, crossing["point"]) < 8 for crossing in crossings)


def find_edge_crossings(
    edges: list[dict[str, Any]], nodes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return visible crossings between unrelated edge paths."""
    endpoints = []
    for edge in edges:
        points = edge["points"]
        endpoints.append(
            {
                "source": nearest_node_index(points[0], nodes),
                "target": nearest_node_index(points[-1], nodes),
                "first": points[0],
                "last": points[-1],
            }
        )

    crossings = []
    for first_index, first_edge in enumerate(edges):
        for second_index, second_edge in enumerate(edges[first_index + 1 :], first_index + 1):
            first_endpoints = endpoints[first_index]
            second_endpoints = endpoints[second_index]
            shared_nodes = {
                first_endpoints["source"],
                first_endpoints["target"],
            }.intersection({second_endpoints["source"], second_endpoints["target"]})
            if shared_nodes:
                continue
            first_points = first_edge["points"]
            second_points = second_edge["points"]
            for first_point_index, first_point in enumerate(first_points[:-1]):
                first_next = first_points[first_point_index + 1]
                for second_point_index, second_point in enumerate(second_points[:-1]):
                    second_next = second_points[second_point_index + 1]
                    intersection = segment_intersection(
                        first_point, first_next, second_point, second_next
                    )
                    if intersection is None:
                        continue
                    if point_inside_any_node(intersection, nodes):
                        continue
                    if crossing_already_counted(intersection, crossings):
                        continue
                    crossings.append(
                        {
                            "first_edge": first_edge["index"],
                            "first_label": first_edge["label"],
                            "first_class": first_edge["className"],
                            "first_crossing_ok": first_edge["crossingOk"],
                            "second_edge": second_edge["index"],
                            "second_label": second_edge["label"],
                            "second_class": second_edge["className"],
                            "second_crossing_ok": second_edge["crossingOk"],
                            "accepted": first_edge["crossingOk"] and second_edge["crossingOk"],
                            "point": {
                                "x": round(intersection["x"], 1),
                                "y": round(intersection["y"], 1),
                            },
                        }
                    )
    return crossings


def print_summary(
    html_path: Path,
    screenshot_path: Path,
    geometry: dict[str, Any],
    node_overlaps: list[dict[str, Any]],
    duplicate_nodes: list[dict[str, Any]],
    edge_occlusions: list[dict[str, Any]],
    edge_crossings: list[dict[str, Any]],
) -> None:
    """Print the visual layout check summary."""
    print(f"html: {html_path}")
    print(f"screenshot: {screenshot_path}")
    print(f"nodes: {len(geometry['nodes'])}")
    print(f"edges: {len(geometry['edges'])}")
    print(f"node_overlaps: {len(node_overlaps)}")
    print(f"duplicate_nodes: {len(duplicate_nodes)}")
    print(f"text_spills: {len(geometry['textSpills'])}")
    print(f"edge_node_overlaps: {len(edge_occlusions)}")
    unaccepted_crossings = [
        crossing for crossing in edge_crossings if not crossing["accepted"]
    ]
    print(f"edge_crossings: {len(edge_crossings)}")
    print(f"unaccepted_edge_crossings: {len(unaccepted_crossings)}")
    for overlap in node_overlaps:
        print(
            "node_overlap:",
            overlap["first"],
            "<->",
            overlap["second"],
            f"area={overlap['area']}",
            f"ratio={overlap['ratio']}",
        )
    for duplicate in duplicate_nodes:
        print(
            "duplicate_node:",
            duplicate["label"],
            f"count={duplicate['count']}",
        )
    for spill in geometry["textSpills"]:
        print("text_spill:", spill["node"], "::", spill["text"])
    for occlusion in edge_occlusions:
        print(
            "edge_node_overlap:",
            f"edge={occlusion['edge']}",
            f"class={occlusion['class']}",
            f"source={occlusion['source']}",
            f"target={occlusion['target']}",
            f"occluded_px={occlusion['occluded_px']}",
            "nodes=" + " | ".join(occlusion["nodes"]),
        )
    for crossing in edge_crossings[:20]:
        print(
            "edge_crossing:",
            f"edge={crossing['first_edge']}:{crossing['first_label']}:{crossing['first_class']}",
            "<->",
            f"edge={crossing['second_edge']}:{crossing['second_label']}:{crossing['second_class']}",
            f"at=({crossing['point']['x']}, {crossing['point']['y']})",
            f"accepted={crossing['accepted']}",
        )


def main() -> int:
    """Run the visual layout check."""
    args = parse_args()
    geometry = render_page(args.html, args.screenshot, args.width, args.height)
    node_overlaps = find_node_overlaps(geometry["nodes"])
    duplicate_nodes = find_duplicate_nodes(geometry["nodes"])
    edge_occlusions = find_edge_occlusions(geometry["edges"], geometry["nodes"])
    edge_crossings = find_edge_crossings(geometry["edges"], geometry["nodes"])
    unaccepted_crossings = [
        crossing for crossing in edge_crossings if not crossing["accepted"]
    ]
    print_summary(
        args.html,
        args.screenshot,
        geometry,
        node_overlaps,
        duplicate_nodes,
        edge_occlusions,
        edge_crossings,
    )
    failed = (
        len(node_overlaps) > 0
        or len(duplicate_nodes) > NODE_DUPLICATE_LIMIT
        or len(geometry["textSpills"]) > 0
        or len(edge_occlusions) > 0
        or len(unaccepted_crossings) > EDGE_CROSSING_LIMIT
    )
    if failed:
        print("result: FAIL")
        return 1
    print("result: PASS")
    return 0


sys.exit(main())
