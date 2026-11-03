# Proposal: slider-to-verify human kinematics gate

Status: implemented
Date: 2026-10-27

## Problem

Protecting endpoints against automated scraping and headless browser scripts often requires distinguishing real human motor input from synthetic bot manipulation.
While `challenge` (stateless PoW) raises CPU cost, and `humanverify` (press-and-hold) captures coarse hold signals, automated scripts can attempt to fake simple stationary events or constant-speed linear drags.

We need an interactive, user-friendly sliding verification mechanism (`sliderverify`) that evaluates biological motor control (Fitts's Law, velocity profiles, non-zero orthogonal jitter/micro-tremors, target accuracy, realistic duration) while remaining stateless, dependency-free, and aligned with botdetect's architecture.

## Proposal

Add `botdetect/sliderverify`:
- **Stateless cryptographic tokens**: HMAC-SHA256 signed tokens encoding issue timestamp, random target position percentage (50–90%), client fingerprint binding (UA + IP), and nonce.
- **Embedded UI**: Clean, responsive sliding track with visual target zone and embedded drag tracker (`sliderverify.js`).
- **Kinematics analysis**:
  1. *Fitts's Law velocity curve*: Biological motion exhibits bell-shaped velocity profiles (acceleration -> peak velocity -> deceleration). Linear or constant-speed synthetic scripts are rejected.
  2. *Orthogonal jitter (Y-axis microtremor)*: Natural human hand movements always demonstrate subtle orthogonal variance. Straight line / zero-jitter mouse events are rejected.
  3. *Target zone precision*: Validates whether the slider landed within the tolerance band of the randomized target position.
  4. *Anti-teleportation & duration checks*: Fast-forward bot clicks (<350ms) and instantaneous coordinate jumps are flagged.
- **Pass cookie & replay store**: Signs an HMAC pass cookie upon success. Supports optional `ReplayStore` for single-use token consumption.
- **Middleware**: Intercepts requests, serves challenge page on unauthorized GET/HEAD, validates verification POSTs, and protects downstream handlers.
