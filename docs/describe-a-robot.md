# Describe a robot: what affects it?

Describe your device once in plain terms (no CVE or EMB3D knowledge needed)
and get a ranked list of the vulnerabilities that apply to it, each with the
reason it applies. Run these after loading the threat
intel (next section).

```bash
glitched onboard          # 1. answer ~15 yes/no questions -> writes glitch.yaml
glitched exposure         # 2. re-check any time; anything new is flagged NEW
glitched scan --profile glitch.yaml --host <robot-ip> \
  --authorization "self-owned lab device"   # 3. verify on a lab device, scoped to your profile
```

Add detail to the profile at any time (merging never removes anything):

```bash
glitched profile import-sbom sbom.json      # CycloneDX or SPDX JSON
glitched profile detect --host <robot-ip>   # connect-only port scan; you confirm each suggestion
glitched exposure --refresh                 # re-pull MITRE + research CVEs first
```

`glitch.yaml` is plain YAML, so you can write it by hand or check it into your repo:

```yaml
name: warehouse-amr-v3
platforms: [ros, unitree]          # ros, universal-robots, unitree, lerobot
ros_distro: humble                 # for ROS robots: decides which ROS CVEs apply
interfaces: [wifi, bluetooth, mqtt]
ml: true                           # also match MITRE ATLAS ML techniques
properties: [PID-41, PID-275]      # EMB3D ids; the questionnaire fills these in
```

A CVE applies when it names a platform the device is built on, or when NVD lists
one of the SBOM's components as affected - and, if the SBOM gives a version,
that version is in NVD's affected range. ROS is an ecosystem rather than one
product, so for ROS robots set the distro (`ros_distro: humble` in `glitch.yaml`,
or the onboarding question): core ROS CVEs then apply by ROS generation and
distro, while CVEs about one package (nav2, MoveIt, ...) apply only when the SBOM
lists it (Debian names like `ros-humble-navigation2` are understood).

You don't need a formal SBOM: on the robot, run `dpkg-query -W` (or `dpkg -l`,
`pip freeze`, `ros2 pkg list`) and paste the output into **Robot details** in the
UI, or save it to a file and run `glitched profile import-sbom packages.txt`.
Debian versions are compared by their upstream part (`1:1.3.11-1jammy…` → 1.3.11). CVEs in
other products that merely share a keyword (Wi-Fi, MQTT, "ROS") are hidden;
`glitched exposure --related` lists them, each with why.
