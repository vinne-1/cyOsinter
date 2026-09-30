import { useEffect, useRef, useState } from "react";

export type CatMood = "idle" | "thinking" | "happy" | "sad";

/**
 * A small animated cat-head avatar for the in-app assistant, built entirely
 * from inline SVG/CSS — no image asset to ship or license. "Dynamic" here
 * means it reacts to the assistant's state rather than being a static icon:
 * it blinks on an idle timer, and its eyes shift to a distinct look while a
 * reply is pending, after a successful answer, and after a failed one.
 */
export function CatHead({ mood = "idle", size = 28 }: { mood?: CatMood; size?: number }) {
  const [blink, setBlink] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    // Blink only in the idle/happy states — mid-thought or mid-error the cat
    // keeps its eyes on you, which reads as more "alive" than a fixed timer
    // blinking through every state regardless of what is happening.
    if (mood !== "idle" && mood !== "happy") return;
    let cancelled = false;
    const schedule = () => {
      const delay = 2600 + Math.random() * 2400;
      timeoutRef.current = setTimeout(() => {
        if (cancelled) return;
        setBlink(true);
        setTimeout(() => {
          if (!cancelled) setBlink(false);
        }, 140);
        schedule();
      }, delay);
    };
    schedule();
    return () => {
      cancelled = true;
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, [mood]);

  const eyeRy = blink ? 0.4 : mood === "sad" ? 2.6 : 3.2;
  const pupilClass = mood === "thinking" ? "cat-pupil-think" : "";
  const mouthPath =
    mood === "happy"
      ? "M 11 20 Q 14 23 17 20"
      : mood === "sad"
        ? "M 11 21 Q 14 18.5 17 21"
        : "M 11.5 20.5 Q 14 21.5 16.5 20.5";

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 28 28"
      fill="none"
      aria-hidden="true"
      className="shrink-0"
    >
      <style>{`
        @keyframes cat-pupil-think {
          0%, 100% { transform: translateX(-1.1px); }
          50% { transform: translateX(1.1px); }
        }
        .cat-pupil-think { animation: cat-pupil-think 1.1s ease-in-out infinite; }
      `}</style>
      {/* ears */}
      <path d="M4 9 L8 2 L10.5 10Z" fill="currentColor" opacity={0.9} />
      <path d="M24 9 L20 2 L17.5 10Z" fill="currentColor" opacity={0.9} />
      {/* head */}
      <circle cx="14" cy="15.5" r="10.5" fill="currentColor" />
      {/* eyes (white) */}
      <ellipse cx="10.3" cy="14.5" rx="3.1" ry={eyeRy} fill="var(--cat-eye, white)" style={{ transition: "ry 90ms ease" }} />
      <ellipse cx="17.7" cy="14.5" rx="3.1" ry={eyeRy} fill="var(--cat-eye, white)" style={{ transition: "ry 90ms ease" }} />
      {/* pupils */}
      {!blink && (
        <g className={pupilClass}>
          <circle cx="10.3" cy="14.7" r="1.4" fill="var(--cat-pupil, #0b1220)" />
          <circle cx="17.7" cy="14.7" r="1.4" fill="var(--cat-pupil, #0b1220)" />
        </g>
      )}
      {/* nose */}
      <path d="M13 18 L15 18 L14 19.3Z" fill="var(--cat-eye, white)" opacity={0.85} />
      {/* mouth */}
      <path d={mouthPath} stroke="var(--cat-eye, white)" strokeWidth="1.1" strokeLinecap="round" fill="none" opacity={0.85} />
      {/* whiskers */}
      <g stroke="currentColor" strokeWidth="0.8" opacity={0.55}>
        <line x1="2" y1="16" x2="7" y2="16.5" />
        <line x1="2" y1="19" x2="7" y2="18.5" />
        <line x1="26" y1="16" x2="21" y2="16.5" />
        <line x1="26" y1="19" x2="21" y2="18.5" />
      </g>
    </svg>
  );
}
