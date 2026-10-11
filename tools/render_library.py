"""
Renders the robot picture library (src/glitched/web_static/library/renders):
procedural 3D models lit like product shots, rendered with Cycles on a
transparent background, and the 2D position of each part, projected from its
3D point so the UI's part markers sit exactly on the model.

    /Applications/Blender.app/Contents/MacOS/Blender -b --factory-startup \
        -P tools/render_library.py -- OUTDIR [wheeled arm ...]

Writes OUTDIR/<id>.png and OUTDIR/anchors.json; copy the PNGs to
library/renders/ and the anchors into library/library.json. Needs Blender 4.2+.
"""

import json
import math
import sys
from pathlib import Path

import bpy
from bpy_extras.object_utils import world_to_camera_view
from mathutils import Vector

OUT = Path(sys.argv[sys.argv.index("--") + 1])
ONLY = sys.argv[sys.argv.index("--") + 2:] or None
SIZE = 960

# --------------------------------------------------------------------------
# Scene helpers
# --------------------------------------------------------------------------

MATS = {}


def mat(name, color, metallic=0.0, rough=0.4, coat=0.0, emit=None, strength=4.0):
    if name in MATS:
        return MATS[name]
    m = bpy.data.materials.new(name)
    m.use_nodes = True
    p = m.node_tree.nodes["Principled BSDF"]
    p.inputs["Base Color"].default_value = (*color, 1)
    p.inputs["Metallic"].default_value = metallic
    p.inputs["Roughness"].default_value = rough
    p.inputs["Coat Weight"].default_value = coat
    if emit:
        p.inputs["Emission Color"].default_value = (*emit, 1)
        p.inputs["Emission Strength"].default_value = strength
    MATS[name] = m
    return m


def materials():
    return {
        "white": mat("white", (0.80, 0.80, 0.78), rough=0.32, coat=0.25),
        "grey": mat("grey", (0.55, 0.58, 0.62), rough=0.35, coat=0.2),
        "graphite": mat("graphite", (0.045, 0.048, 0.055), metallic=0.25, rough=0.42),
        "alu": mat("alu", (0.72, 0.73, 0.75), metallic=1.0, rough=0.28),
        "rubber": mat("rubber", (0.015, 0.015, 0.015), rough=0.85),
        "glass": mat("glass", (0.008, 0.01, 0.014), rough=0.06, coat=1.0),
        "accent": mat("accent", (0.88, 0.52, 0.10), rough=0.4),
        "led": mat("led", (0.9, 0.55, 0.1), emit=(1.0, 0.55, 0.1), strength=6),
        "led_green": mat("led_green", (0.1, 0.9, 0.3), emit=(0.15, 1.0, 0.35), strength=5),
        "port": mat("port", (0.01, 0.01, 0.01), rough=0.7),
        "red": mat("red", (0.75, 0.05, 0.04), rough=0.35, coat=0.3),
        "blue": mat("blue", (0.05, 0.18, 0.6), rough=0.4),
    }


def _finish(obj, m, bevel, segments=3):
    obj.data.materials.append(m)
    if bevel:
        mod = obj.modifiers.new("Bevel", "BEVEL")
        mod.width = bevel
        mod.segments = segments
        mod.limit_method = "ANGLE"
        bpy.context.view_layer.objects.active = obj
        bpy.ops.object.modifier_apply(modifier=mod.name)
    bpy.context.view_layer.objects.active = obj
    obj.select_set(True)
    bpy.ops.object.shade_smooth_by_angle(angle=math.radians(35))
    obj.select_set(False)
    return obj


def box(size, loc, m, bevel=0.02, rot=(0, 0, 0)):
    bpy.ops.mesh.primitive_cube_add(size=1, location=loc, rotation=rot)
    obj = bpy.context.active_object
    obj.scale = size
    bpy.ops.object.transform_apply(scale=True)
    return _finish(obj, m, min(bevel, min(size) * 0.45))


def cyl(r, depth, loc, m, rot=(0, 0, 0), bevel=0.006, verts=64):
    bpy.ops.mesh.primitive_cylinder_add(radius=r, depth=depth, location=loc, rotation=rot, vertices=verts)
    return _finish(bpy.context.active_object, m, min(bevel, r * 0.4, depth * 0.4))


def sph(r, loc, m, scale=(1, 1, 1)):
    bpy.ops.mesh.primitive_uv_sphere_add(radius=r, location=loc, segments=48, ring_count=24)
    obj = bpy.context.active_object
    obj.scale = scale
    bpy.ops.object.transform_apply(scale=True)
    return _finish(obj, m, 0)


def tube(a, b, r, m, bevel=0.004):
    a, b = Vector(a), Vector(b)
    d = b - a
    bpy.ops.mesh.primitive_cylinder_add(radius=r, depth=d.length, location=(a + b) / 2, vertices=48)
    obj = bpy.context.active_object
    obj.rotation_mode = "QUATERNION"
    obj.rotation_quaternion = d.to_track_quat("Z", "Y")
    return _finish(obj, m, min(bevel, r * 0.4))


X90 = (math.pi / 2, 0, 0)
Y90 = (0, math.pi / 2, 0)

# --------------------------------------------------------------------------
# The robots. Each returns {part: 3D point}; the front faces -Y (or -X).
# --------------------------------------------------------------------------


def wheeled(M):
    box((0.72, 0.52, 0.18), (0, 0, 0.17), M["graphite"], 0.04)
    box((0.64, 0.05, 0.07), (0, -0.27, 0.12), M["rubber"], 0.02)
    for x in (-0.31, 0.31):
        for y in (-0.17, 0.17):
            cyl(0.095, 0.07, (x, y + (0.0), 0.095), M["rubber"], Y90, 0.02)
            cyl(0.04, 0.074, (x, y, 0.095), M["graphite"], Y90, 0.008)
            cyl(0.018, 0.078, (x, y, 0.095), M["alu"], Y90, 0.004)
    box((0.54, 0.44, 0.50), (0, 0, 0.51), M["white"], 0.07)
    box((0.48, 0.38, 0.06), (0, 0, 0.78), M["white"], 0.03)
    box((0.50, 0.012, 0.025), (0, -0.222, 0.32), M["led"], 0.006)
    box((0.36, 0.014, 0.17), (0, -0.222, 0.62), M["glass"], 0.02)
    cyl(0.042, 0.03, (0, -0.226, 0.46), M["alu"], X90, 0.006)
    cyl(0.03, 0.035, (0, -0.229, 0.46), M["glass"], X90, 0.004)
    box((0.012, 0.14, 0.07), (0.272, -0.06, 0.40), M["graphite"], 0.008)
    for i, y in enumerate((-0.09, -0.04)):
        box((0.006, 0.03, 0.018), (0.279, y, 0.40), M["port"], 0.002)
    box((0.16, 0.012, 0.05), (0.18, -0.262, 0.20), M["graphite"], 0.006)
    for x in (0.14, 0.18, 0.22):
        box((0.022, 0.006, 0.012), (x, -0.269, 0.20), M["port"], 0.002)
    cyl(0.025, 0.18, (0.13, 0.09, 0.9), M["alu"])
    cyl(0.068, 0.07, (0.13, 0.09, 1.02), M["graphite"], bevel=0.015)
    cyl(0.069, 0.022, (0.13, 0.09, 1.02), M["glass"], bevel=0.004)
    cyl(0.008, 0.17, (-0.18, 0.13, 0.89), M["rubber"])
    sph(0.014, (-0.18, 0.13, 0.98), M["rubber"])
    return {"network": (-0.18, 0.13, 0.96), "cloud_link": (0.13, 0.09, 1.06),
            "main_controller": (-0.09, -0.23, 0.62), "debug_port": (0.28, -0.06, 0.40),
            "peripherals": (0.18, -0.27, 0.20)}


def arm(M):
    box((0.56, 0.46, 0.60), (0, 0, 0.38), M["graphite"], 0.03)
    box((0.58, 0.48, 0.025), (0, 0, 0.69), M["alu"], 0.008)
    for x in (-0.22, 0.22):
        for y in (-0.17, 0.17):
            cyl(0.012, 0.04, (x, y, 0.06), M["alu"])
            sph(0.035, (x, y, 0.035), M["rubber"])
    tube((-0.2, 0.26, 0.55), (-0.2, 0.26, 0.72), 0.012, M["alu"])
    tube((0.2, 0.26, 0.55), (0.2, 0.26, 0.72), 0.012, M["alu"])
    tube((-0.2, 0.26, 0.72), (0.2, 0.26, 0.72), 0.012, M["alu"])
    cyl(0.03, 0.025, (0.2, -0.235, 0.62), M["red"], X90, 0.006)
    box((0.30, 0.012, 0.10), (-0.06, -0.232, 0.50), M["graphite"], 0.006)
    for x in (-0.16, -0.12):
        box((0.028, 0.006, 0.022), (x, -0.239, 0.51), M["port"], 0.002)
    box((0.05, 0.006, 0.015), (0.02, -0.239, 0.51), M["port"], 0.002)
    sph(0.007, (0.07, -0.238, 0.53), M["led_green"])
    box((0.006, 0.07, 0.04), (-0.281, 0.02, 0.36), M["alu"], 0.003)
    box((0.004, 0.04, 0.016), (-0.284, 0.02, 0.36), M["port"], 0.002)
    box((0.03, 0.2, 0.28), (0.3, -0.05, 0.42), M["graphite"], 0.02, rot=(0, 0.12, 0))
    box((0.006, 0.15, 0.17), (0.317, -0.05, 0.44), M["glass"], 0.01, rot=(0, 0.12, 0))
    cyl(0.008, 0.12, (0.24, 0.2, 0.76), M["rubber"])
    # A six-axis collaborative arm
    cyl(0.08, 0.06, (0, 0.04, 0.73), M["white"], bevel=0.015)
    cyl(0.07, 0.16, (0, 0.04, 0.82), M["white"], bevel=0.02)
    cyl(0.072, 0.03, (0, 0.04, 0.905), M["grey"], bevel=0.006)
    S, E, W1, W2, T = (0, 0.04, 0.96), (0, -0.16, 1.30), (0, -0.44, 1.16), (0, -0.50, 1.07), (0, -0.50, 0.95)
    cyl(0.072, 0.17, S, M["white"], Y90, 0.02)
    cyl(0.074, 0.03, (-0.085, *S[1:]), M["grey"], Y90, 0.006)
    tube(S, E, 0.046, M["white"], 0.01)
    cyl(0.062, 0.15, E, M["white"], Y90, 0.02)
    cyl(0.064, 0.025, (-0.075, E[1], E[2]), M["grey"], Y90, 0.005)
    tube(E, W1, 0.038, M["white"], 0.01)
    cyl(0.05, 0.12, W1, M["white"], Y90, 0.015)
    tube(W1, W2, 0.038, M["white"])
    cyl(0.045, 0.1, W2, M["white"], bevel=0.012)
    cyl(0.04, 0.05, (0, -0.50, 1.0), M["grey"], bevel=0.008)
    box((0.08, 0.09, 0.05), T, M["graphite"], 0.012)
    for x in (-0.025, 0.025):
        box((0.014, 0.035, 0.08), (x, -0.50, 0.89), M["alu"], 0.004)
    return {"network": (-0.14, -0.24, 0.51), "cloud_link": (0.24, 0.2, 0.83),
            "main_controller": (0, -0.23, 0.33), "debug_port": (-0.285, 0.02, 0.36),
            "peripherals": (0, -0.5, 0.9)}


def quadruped(M):
    box((0.62, 0.27, 0.15), (0, 0, 0.42), M["grey"], 0.05)
    box((0.42, 0.2, 0.035), (0.03, 0, 0.505), M["graphite"], 0.012)
    box((0.13, 0.23, 0.13), (-0.355, 0, 0.44), M["grey"], 0.04)
    box((0.012, 0.19, 0.07), (-0.42, 0, 0.445), M["glass"], 0.008)
    for y in (-0.05, 0.05):
        sph(0.013, (-0.427, y, 0.45), M["glass"])
    sph(0.05, (-0.34, 0, 0.51), M["graphite"], (1, 1, 0.8))
    box((0.06, 0.012, 0.025), (0.22, -0.137, 0.43), M["graphite"], 0.004)
    box((0.03, 0.006, 0.012), (0.22, -0.143, 0.43), M["port"], 0.002)
    cyl(0.007, 0.12, (0.2, 0.08, 0.58), M["rubber"])
    for x in (-0.22, 0.24):
        for y in (-0.165, 0.165):
            hip = (x, y, 0.41)
            knee = (x + 0.07, y * 1.08, 0.24)
            foot = (x - 0.02, y * 1.08, 0.035)
            cyl(0.055, 0.07, hip, M["graphite"], X90, 0.012)
            tube(hip, knee, 0.036, M["grey"], 0.01)
            sph(0.036, knee, M["graphite"])
            tube(knee, foot, 0.019, M["graphite"])
            sph(0.032, foot, M["rubber"])
    return {"network": (-0.42, 0, 0.45), "cloud_link": (0.2, 0.08, 0.64),
            "main_controller": (0.0, -0.137, 0.42), "debug_port": (0.22, -0.145, 0.43),
            "peripherals": (0.03, 0, 0.525)}


def humanoid(M):
    box((0.30, 0.18, 0.14), (0, 0, 0.92), M["graphite"], 0.03)
    box((0.42, 0.25, 0.44), (0, 0, 1.22), M["white"], 0.07)
    box((0.22, 0.012, 0.15), (0, -0.126, 1.29), M["glass"], 0.015)
    box((0.18, 0.012, 0.012), (0, -0.126, 1.19), M["led"], 0.004)
    box((0.30, 0.10, 0.30), (0, 0.17, 1.22), M["graphite"], 0.03)
    cyl(0.042, 0.07, (0, 0, 1.47), M["graphite"])
    box((0.21, 0.21, 0.23), (0, 0, 1.61), M["white"], 0.07)
    box((0.17, 0.012, 0.075), (0, -0.106, 1.63), M["glass"], 0.012)
    cyl(0.006, 0.08, (0.06, 0.02, 1.76), M["rubber"])
    box((0.012, 0.05, 0.03), (0.215, -0.05, 1.08), M["graphite"], 0.004)
    box((0.04, 0.008, 0.02), (0.06, -0.092, 0.93), M["port"], 0.003)
    for s in (-1, 1):
        sh, el, wr = (s * 0.26, 0, 1.38), (s * 0.30, -0.03, 1.10), (s * 0.31, -0.09, 0.87)
        sph(0.058, sh, M["graphite"])
        tube(sh, el, 0.042, M["white"], 0.01)
        sph(0.043, el, M["graphite"])
        tube(el, wr, 0.035, M["white"], 0.01)
        box((0.05, 0.07, 0.11), (wr[0], wr[1], wr[2] - 0.06), M["graphite"], 0.015)
        hp, kn, an = (s * 0.10, 0, 0.85), (s * 0.11, -0.02, 0.48), (s * 0.11, 0, 0.10)
        sph(0.062, hp, M["graphite"])
        tube(hp, kn, 0.057, M["white"], 0.012)
        sph(0.052, kn, M["graphite"])
        tube(kn, an, 0.046, M["white"], 0.012)
        box((0.10, 0.23, 0.06), (s * 0.11, -0.03, 0.035), M["graphite"], 0.02)
    return {"network": (0, -0.11, 1.63), "cloud_link": (0.06, 0.02, 1.80),
            "main_controller": (0, -0.13, 1.29), "debug_port": (0.06, -0.095, 0.93),
            "peripherals": (0.22, -0.05, 1.08)}


def drone(M):
    box((0.24, 0.32, 0.085), (0, 0, 0.30), M["white"], 0.035)
    box((0.19, 0.25, 0.03), (0, 0, 0.355), M["white"], 0.012)
    box((0.10, 0.012, 0.02), (0, -0.162, 0.30), M["glass"], 0.004)
    for sx in (-1, 1):
        for sy in (-1, 1):
            m = (sx * 0.31, sy * 0.31, 0.33)
            tube((sx * 0.08, sy * 0.1, 0.32), m, 0.016, M["graphite"])
            cyl(0.034, 0.045, m, M["graphite"], bevel=0.008)
            cyl(0.012, 0.02, (m[0], m[1], 0.362), M["alu"])
            ang = 0.5 if sx * sy > 0 else -0.5
            box((0.32, 0.034, 0.004), (m[0], m[1], 0.372), M["graphite"], 0.002, rot=(0, 0, ang))
            sph(0.008, (m[0], m[1], 0.307), M["led"] if sy < 0 else M["led_green"])
    for sx in (-1, 1):
        tube((sx * 0.07, -0.08, 0.26), (sx * 0.12, -0.10, 0.05), 0.009, M["graphite"])
        tube((sx * 0.07, 0.08, 0.26), (sx * 0.12, 0.10, 0.05), 0.009, M["graphite"])
        tube((sx * 0.12, -0.16, 0.045), (sx * 0.12, 0.16, 0.045), 0.011, M["graphite"])
    cyl(0.02, 0.03, (0, -0.10, 0.245), M["graphite"])
    sph(0.048, (0, -0.10, 0.20), M["graphite"])
    cyl(0.024, 0.02, (0, -0.147, 0.20), M["glass"], X90, 0.004)
    cyl(0.008, 0.07, (0, 0.08, 0.40), M["alu"])
    cyl(0.032, 0.016, (0, 0.08, 0.44), M["white"], bevel=0.006)
    box((0.012, 0.03, 0.016), (-0.121, 0.06, 0.30), M["port"], 0.003)
    return {"network": (0, -0.05, 0.372), "cloud_link": (0, 0.08, 0.45),
            "main_controller": (0, -0.163, 0.30), "debug_port": (-0.123, 0.06, 0.30),
            "peripherals": (0, -0.15, 0.20)}


def generic(M):
    box((0.36, 0.26, 0.10), (0, 0, 0.065), M["graphite"], 0.012)
    for i in range(13):
        box((0.008, 0.24, 0.035), (-0.165 + i * 0.0275, 0, 0.13), M["graphite"], 0.002)
    for x in (-0.15, 0.15):
        for y in (-0.1, 0.1):
            cyl(0.02, 0.012, (x, y, 0.009), M["rubber"])
    box((0.34, 0.006, 0.075), (0, -0.131, 0.065), M["alu"], 0.003)
    for x in (-0.135, -0.1):
        box((0.026, 0.006, 0.022), (x, -0.135, 0.07), M["port"], 0.003)
        sph(0.003, (x - 0.008, -0.138, 0.084), M["led_green"])
    for x in (-0.055, -0.035):
        box((0.014, 0.006, 0.006), (x, -0.135, 0.075), M["blue"], 0.001)
    box((0.036, 0.006, 0.013), (0.045, -0.135, 0.07), M["port"], 0.003)
    box((0.014, 0.006, 0.014), (0.11, -0.135, 0.07), M["port"], 0.002)
    sph(0.004, (0.14, -0.136, 0.07), M["led"])
    for x in (-0.15, 0.15):
        cyl(0.012, 0.02, (x, 0.12, 0.125), M["alu"])
        tube((x, 0.12, 0.13), (x * 1.15, 0.13, 0.31), 0.009, M["rubber"])
    return {"network": (-0.118, -0.136, 0.07), "cloud_link": (0.172, 0.13, 0.31),
            "main_controller": (0.0, -0.02, 0.15), "debug_port": (0.045, -0.136, 0.07),
            "peripherals": (-0.045, -0.136, 0.075)}


# id -> (builder, camera direction from the robot)
ROBOTS = {
    "wheeled": (wheeled, (-0.55, -1.0, 0.42)),
    "arm": (arm, (-0.6, -1.0, 0.42)),
    "quadruped": (quadruped, (-1.0, -0.75, 0.38)),
    "humanoid": (humanoid, (-0.45, -1.0, 0.25)),
    "drone": (drone, (-0.6, -1.0, 0.55)),
    "generic": (generic, (-0.55, -1.0, 0.6)),
}

# --------------------------------------------------------------------------
# Lights, camera, render
# --------------------------------------------------------------------------


def setup_render(scene):
    scene.render.engine = "CYCLES"
    prefs = bpy.context.preferences.addons["cycles"].preferences
    prefs.compute_device_type = "METAL"
    prefs.get_devices()
    for d in prefs.devices:
        d.use = True
    scene.cycles.device = "GPU"
    scene.cycles.samples = 160
    scene.cycles.use_denoising = True
    scene.render.film_transparent = True
    scene.render.resolution_x = scene.render.resolution_y = SIZE
    scene.render.image_settings.file_format = "PNG"
    scene.render.image_settings.color_mode = "RGBA"
    scene.render.image_settings.compression = 100
    scene.view_settings.view_transform = "AgX"
    try:
        scene.view_settings.look = "AgX - Punchy"
    except TypeError:
        pass
    scene.view_settings.exposure = -0.1
    world = bpy.data.worlds.new("world")
    scene.world = world
    world.use_nodes = True
    bg = world.node_tree.nodes["Background"]
    bg.inputs["Color"].default_value = (0.75, 0.76, 0.78, 1)
    bg.inputs["Strength"].default_value = 0.18


def light(name, loc, energy, size, target, shadow=True):
    data = bpy.data.lights.new(name, "AREA")
    data.energy, data.size = energy, size
    data.use_shadow = shadow  # only the key light casts a shadow onto the floor
    obj = bpy.data.objects.new(name, data)
    bpy.context.collection.objects.link(obj)
    obj.location = loc
    obj.rotation_euler = (Vector(target) - Vector(loc)).to_track_quat("-Z", "Y").to_euler()


def render(rid):
    bpy.ops.wm.read_factory_settings(use_empty=True)
    MATS.clear()
    scene = bpy.context.scene
    setup_render(scene)
    builder, direction = ROBOTS[rid]
    points = builder(materials())

    meshes = [o for o in scene.objects if o.type == "MESH"]
    corners = [o.matrix_world @ Vector(c) for o in meshes for c in o.bound_box]
    lo = Vector((min(c.x for c in corners), min(c.y for c in corners), min(c.z for c in corners)))
    hi = Vector((max(c.x for c in corners), max(c.y for c in corners), max(c.z for c in corners)))
    center = (lo + hi) / 2

    bpy.ops.mesh.primitive_plane_add(size=12, location=(center.x, center.y, lo.z))
    bpy.context.active_object.is_shadow_catcher = True

    cam_data = bpy.data.cameras.new("cam")
    cam_data.lens = 70
    cam = bpy.data.objects.new("cam", cam_data)
    bpy.context.collection.objects.link(cam)
    scene.camera = cam
    d = Vector(direction).normalized()
    dist = (hi - lo).length * 2.2
    for _ in range(6):  # fit the robot to ~84% of the frame
        cam.location = center + d * dist
        cam.rotation_euler = (center - cam.location).to_track_quat("-Z", "Y").to_euler()
        bpy.context.view_layer.update()
        proj = [world_to_camera_view(scene, cam, c) for c in corners]
        spread = max(max(abs(p.x - 0.5), abs(p.y - 0.5)) for p in proj)
        dist *= spread / 0.42
    # Recentre on the projected bounds.
    proj = [world_to_camera_view(scene, cam, c) for c in corners]
    cam_data.shift_x = ((min(p.x for p in proj) + max(p.x for p in proj)) / 2 - 0.5)
    cam_data.shift_y = ((min(p.y for p in proj) + max(p.y for p in proj)) / 2 - 0.5)
    bpy.context.view_layer.update()

    r = (hi - lo).length
    # Key mostly overhead so the shadow pools under the robot; fill and rim stay soft.
    light("key", center + Vector((-0.7, -0.9, 2.6)) * r, 260 * r * r, 1.0 * r, center)
    light("fill", center + Vector((1.9, -1.0, 0.9)) * r, 70 * r * r, 2.2 * r, center, shadow=False)
    light("rim", center + Vector((0.5, 2.1, 1.5)) * r, 180 * r * r, 1.0 * r, center, shadow=False)

    scene.render.filepath = str(OUT / f"{rid}.png")
    bpy.ops.render.render(write_still=True)
    anchors = {}
    for part, p in points.items():
        v = world_to_camera_view(scene, cam, Vector(p))
        anchors[part] = [round(v.x, 4), round(1 - v.y, 4)]
    return anchors


OUT.mkdir(parents=True, exist_ok=True)
result = {}
for rid in ROBOTS:
    if ONLY and rid not in ONLY:
        continue
    result[rid] = render(rid)
    print("RENDERED", rid, result[rid], flush=True)
existing = json.loads((OUT / "anchors.json").read_text()) if (OUT / "anchors.json").exists() else {}
existing.update(result)
(OUT / "anchors.json").write_text(json.dumps(existing, indent=1))
