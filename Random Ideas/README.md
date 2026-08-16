# 🌌 Cosmic Atlas — Ultimate Photorealistic Universe Explorer

**Made by Uzan Khan**

An interactive, browser-based 3D universe you can fly through — every planet, moon,
star, galaxy, nebula, black hole, comet, and more, fully navigable with your mouse,
touch screen, keyboard, **or your bare hands** via webcam gesture control.

🔗 **[Live Demo](#-how-to-share-a-live-link)** — see below for how to get this link once it's on GitHub.

---

## ✨ Features

- **600+ real celestial objects** — every planet, dwarf planet, moon, asteroid, comet,
  star, exoplanet, nebula, black hole, pulsar, quasar, star cluster, galaxy cluster,
  Kuiper Belt/Oort Cloud object, and historic space mission, each with its own
  description.
- **Photorealistic rendering** — animated plasma-shader Sun, glowing corona, Earth
  cloud layer + atmosphere, textured planets and rings, twinkling starfield, and
  cinematic bloom post-processing.
- **Four ways to navigate:**
  - 🖱️ **Mouse** — drag to rotate, scroll to zoom, right-drag to pan
  - 📱 **Touch** — one finger to rotate, pinch to zoom, two-finger drag to pan
  - ⌨️ **Keyboard** — `WASD` / arrow keys to fly, `Q`/`E` to rise and fall
  - 🖐️ **Hand gestures** (webcam) — see below
- **Tap-to-select, tap-again-to-deselect** — select any object to fly in and read
  about it; if it's orbiting, the camera rides along with it; tap it again and the
  camera flies back to exactly where you were.
- **Search bar** — type any object's name and jump straight to it.
- **Layer legend** — toggle whole categories (galaxies, nebulae, moons, etc.) on/off.

## 🖐️ Hand Gesture Controls

Runs entirely in your browser using Google's MediaPipe HandLandmarker — no video is
ever sent anywhere, all processing happens on your own device.

| Gesture | Action |
|---|---|
| ✋ Open palm | Idle — just tracks your hand, does nothing |
| ✊ One closed fist | 360° control: move hand left/right to orbit, forward/back to zoom |
| 👆 One finger pointing | Aim at an object to select it |
| ✊✊ Both hands as fists | Superman-style flight — push both fists toward the screen to fly forward, tilt left/right to steer, push harder for a speed boost |

The cursor dot is **blue** when idle and **yellow** when actively controlling something.

## 🛠️ How It Works (for anyone reading the code)

Everything lives in a single file, `universe.html`, built with
[Three.js](https://threejs.org/) (r128) plus a few of its official add-ons:

- `OrbitControls` — the base mouse/touch camera rig everything else builds on top of.
- `EffectComposer` + `UnrealBloomPass` — the glow/bloom post-processing pass.
- `@mediapipe/tasks-vision` (loaded on demand, only if you turn gestures on) — real-time
  hand landmark detection from your webcam.

The script is organized top to bottom into clearly commented sections:

1. **Deterministic PRNG** — every object's position is generated from a seeded random
   function keyed to its name, so the layout is different for every object but stays
   identical across page reloads.
2. **Scene / camera / renderer / composer setup**.
3. **Texture generators** — small canvas-based functions that procedurally paint planet
   surfaces, glows, and ring gradients (no external image files needed).
4. **The Sun** — a custom GLSL shader that animates a plasma-like noise pattern in
   real time.
5. **Solar system builder** (`createSystemBody`) — one reusable function used to build
   every planet, moon, and dwarf planet, including parent/child orbits.
6. **Category builders** — one function per category (stars, exoplanets, galaxies,
   nebulae, black holes, pulsars, quasars, star/galaxy clusters, Kuiper Belt, Oort
   Cloud, exotic objects, missions) that generates that category's objects from a
   plain list of names + descriptions.
7. **Interaction core** — `pickNearestOnScreen()` finds whatever object is visually
   closest to your click/tap in *screen space* (not raw 3D raycasting — this is what
   makes clicking a tiny planet reliable even when a huge galaxy is technically
   "behind" it along the same ray). `selectObject()` handles the select/deselect
   toggle, camera fly-in, and follow-while-orbiting behavior.
8. **Keyboard flight controls**.
9. **Hand gesture module** — an IIFE containing gesture classification
   (`classifyHand`), temporal smoothing/hysteresis (`stabilizeFor`), and the three
   control modes (`orbitFist`, `pointSelect`, `doubleFistFlight`).
10. **Animation loop** — runs every frame: updates orbits, comet tails, pulsar beams,
    quasar jets, camera flight easing, and renders the scene.

## 🚀 Getting It on GitHub

1. Create a free [GitHub](https://github.com) account if you don't have one.
2. Click the **+** icon (top right) → **New repository**.
   - **Repository name:** `cosmic-atlas` (or anything you like)
   - **Description:** `An interactive photorealistic 3D universe explorer — mouse, touch, keyboard & hand-gesture controllable.`
   - Choose **Public** (so anyone can view it)
   - Click **Create repository**
3. On the next page, click **uploading an existing file**, drag in `universe.html`
   and this `README.md`, then click **Commit changes**.

   *(Or, if you prefer the command line:)*
   ```bash
   git init
   git add universe.html README.md
   git commit -m "Cosmic Atlas — initial commit"
   git branch -M main
   git remote add origin https://github.com/<your-username>/cosmic-atlas.git
   git push -u origin main
   ```

## 🔗 How to Share a Live Link

Anyone you send the plain GitHub repo link to will only see the *code*, not the
running app. To get an actual clickable link people can open and use:

1. In your repo, go to **Settings** → **Pages** (left sidebar).
2. Under **Build and deployment → Source**, choose **Deploy from a branch**.
3. Under **Branch**, select `main` and folder `/ (root)`, then **Save**.
4. Wait about a minute, then refresh — GitHub will show your live URL, which looks like:
   ```
   https://<your-username>.github.io/cosmic-atlas/universe.html
   ```
5. That's the link to share with anyone — it opens directly in their browser, on
   desktop or mobile, no download needed.

## 🔍 How People Find It Via Search

Once your GitHub Pages site has been live for a little while and a few people have
visited/linked it, search engines will index it on their own — there's nothing extra
you need to do. If you want to speed that up:

- Add topics to your repo (gear icon next to **About**) like `threejs`,
  `webgl`, `space`, `3d`, `astronomy` — this helps people browsing GitHub itself find it.
- Share the GitHub Pages link (not the repo link) on social media/forums — that's the
  version that's actually indexed as a usable web app.

## 📄 License

Feel free to add an open-source license (MIT is the simplest) via GitHub's
**Add file → Create new file → LICENSE** button, which offers a template picker.

---

*Made by Uzan Khan.*
