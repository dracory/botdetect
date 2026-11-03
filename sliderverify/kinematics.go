package sliderverify

import (
	"encoding/json"
	"errors"
	"math"
	"time"
)

// Point represents a sampled pointer coordinate during the drag.
// T is milliseconds relative to drag start.
// X is track percentage [0..100] or client pixel coordinate.
// Y is orthogonal pixel displacement relative to drag start.
type Point struct {
	T int     `json:"t"`
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// KinematicsReport contains the behavioral drag data sent by the client.
type KinematicsReport struct {
	DurationMS  int     `json:"duration_ms"`
	FinalPos    float64 `json:"final_pos"`
	PointerType string  `json:"pointer_type"`
	Trajectory  []Point `json:"trajectory"`
}

// ParseKinematics decodes JSON-encoded kinematics telemetry.
func ParseKinematics(data []byte) (*KinematicsReport, error) {
	var rep KinematicsReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// ValidateKinematics applies motor-control heuristics to detect human vs script interaction:
// 1. Duration within [minDuration, maxDuration].
// 2. Target landing accuracy within targetTolerance.
// 3. Minimum trajectory sampling points (real browser dragging generates multiple move events).
// 4. Strict monotonicity or instantaneous teleporting rejection.
// 5. Velocity profile analysis: natural biological movement (Fitts's Law) accelerates then decelerates,
//    having non-zero velocity variance, whereas simple bots move linearly at constant speed or instantly.
// 6. Orthogonal jitter (Y-axis microtremor): humans cannot drag a mouse/finger horizontally across
//    a track without subtle orthogonal movements (unless using touch with very low drift, where small variation still exists).
func ValidateKinematics(rep *KinematicsReport, targetPct int, cfg Config) error {
	if rep == nil {
		return errors.New("missing kinematics data")
	}

	// 1. Duration check
	dur := time.Duration(rep.DurationMS) * time.Millisecond
	if dur < cfg.MinDuration {
		return errors.New("drag completed too fast for a human")
	}
	if dur > cfg.MaxDuration {
		return errors.New("drag took longer than human patience")
	}

	// 2. Target landing accuracy
	diff := math.Abs(rep.FinalPos - float64(targetPct))
	if diff > cfg.TargetTolerance {
		return errors.New("slider missed target zone")
	}

	// 3. Trajectory points check
	n := len(rep.Trajectory)
	if n < 5 {
		return errors.New("insufficient trajectory samples")
	}
	if n > 2000 {
		return errors.New("unreasonable trajectory sample flood")
	}

	// Trajectory time check: first point ~0, last point <= durationMS
	first := rep.Trajectory[0]
	last := rep.Trajectory[n-1]
	if first.T < 0 || last.T > rep.DurationMS+150 {
		return errors.New("trajectory timestamps inconsistent with duration")
	}
	if last.T < rep.DurationMS-150 {
		return errors.New("trajectory stopped prematurely before release")
	}

	// Verify monotonic progression of time
	for i := 1; i < n; i++ {
		if rep.Trajectory[i].T < rep.Trajectory[i-1].T {
			return errors.New("time in trajectory goes backward")
		}
	}

	// 4. Check velocity variance and non-linearity
	// Compute segment velocities: dx / dt
	velocities := make([]float64, 0, n-1)
	for i := 1; i < n; i++ {
		dt := float64(rep.Trajectory[i].T - rep.Trajectory[i-1].T)
		if dt <= 0 {
			continue
		}
		dx := math.Abs(rep.Trajectory[i].X - rep.Trajectory[i-1].X)
		v := dx / dt
		velocities = append(velocities, v)
	}

	if len(velocities) < 4 {
		return errors.New("not enough distinct time steps")
	}

	// Calculate velocity variance
	var sumV, sumV2 float64
	for _, v := range velocities {
		sumV += v
		sumV2 += v * v
	}
	meanV := sumV / float64(len(velocities))
	varV := (sumV2 / float64(len(velocities))) - (meanV * meanV)

	// An automated script dragging at constant speed has variance ≈ 0.
	// Human hand movements exhibit acceleration, peak velocity, and deceleration (Fitts's Law).
	if varV < 1e-7 && meanV > 0 {
		return errors.New("velocity profile is unnaturally constant")
	}

	// Check for single-step jump / teleportation (one step accounting for > 90% of movement)
	totalXDistance := math.Abs(last.X - first.X)
	if totalXDistance > 10 { // if moved significantly
		maxStepDX := 0.0
		for i := 1; i < n; i++ {
			dx := math.Abs(rep.Trajectory[i].X - rep.Trajectory[i-1].X)
			if dx > maxStepDX {
				maxStepDX = dx
			}
		}
		if maxStepDX > 0.95*totalXDistance {
			return errors.New("instantaneous teleportation detected")
		}
	}

	// 5. Orthogonal jitter (Y micro-tremor):
	// Real humans dragging horizontally almost always exert minor vertical tremor or curvature.
	// For mouse, Y tremor is virtually guaranteed.
	// For touch or pen, minor tremor occurs, though we are slightly more lenient.
	var yTravel float64
	var distinctY int
	seenY := make(map[int]bool)

	for i := 1; i < n; i++ {
		dy := math.Abs(rep.Trajectory[i].Y - rep.Trajectory[i-1].Y)
		yTravel += dy
		bucket := int(rep.Trajectory[i].Y * 10)
		if !seenY[bucket] {
			seenY[bucket] = true
			distinctY++
		}
	}

	if rep.PointerType == "mouse" {
		// A mouse dragged across the screen with exact 0.0 Y travel or 0 distinct Y values is synthetic.
		if yTravel == 0 && distinctY <= 1 {
			return errors.New("zero orthogonal jitter detected for mouse interaction")
		}
	}

	// Prevent synthetic absurdly high jitter (noise injection bots)
	if yTravel > 20000 {
		return errors.New("excessive synthetic jitter detected")
	}

	return nil
}
