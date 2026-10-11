# The robot scan UI

```bash
glitched ui
```

opens a page in your browser. **Add robot** registers one: its name, address and
why you're allowed to test it, then plain-language questions (the same ones as
`glitched onboard`) and, optionally, an SBOM; **Robot details** changes the
answers later. The page shows each robot drawn as a robot,
every open finding pinned to the part it's in, and a panel for each finding:
what's wrong, the evidence, the recommended fix, and **Recheck**, which re-runs
just that check. **Scan now** runs the passive scan; the first time for each
robot it first shows exactly what will be sent - the address, each check's
ports and requests, and what's never sent - and waits for you to start it
(**What's sent** shows this any time; `glitched device plan <name>` in a
terminal). While it runs, the panel goes through each check live - every
port and request it tries, with the result - and ends with a summary. Robots added with
`glitched device add` show up too.

**Pictures.** Each robot starts with a 3D render from the built-in library that
fits its profile (wheeled robot, robot arm, quadruped, humanoid, drone or
controller box), on a transparent background with its parts already placed
(`tools/render_library.py` makes them in Blender). **Change picture** picks another, or uploads your own photo
(PNG, JPEG or WebP, up to 8 MB). On a photo, **Edit parts** lets you click where
each part is - network, cloud link, main controller, debug port, USB/serial -
and rename them; findings for parts that aren't on the picture stay in the list.
Photos are stored with your other Glitched data (`~/.local/share/glitched/robot-images`)
and never leave your computer; location and other metadata is removed from JPEGs.

The UI runs on your computer only: it listens on `127.0.0.1`, needs the
one-time key in the link `glitched ui` prints (don't share it), and refuses
requests from other websites. It uses the same database, checks and safety
rules as the command line; nothing is sent anywhere else. `--no-browser` prints
the link instead of opening it; `--port` picks the port.
