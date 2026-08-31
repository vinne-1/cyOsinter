import React from "react";
import { cn } from "@/lib/utils";
import { ChevronLeft, ChevronRight } from "lucide-react";

/**
 * A horizontally scrollable strip with edge affordances.
 *
 * A bare `overflow-x-auto` scrolls, but nothing tells the user there is more:
 * the last item is simply sliced off at the container edge, which reads as a
 * layout bug. This adds a fade plus an arrow button on whichever side has more
 * content, and only while that side actually overflows.
 */
export function ScrollStrip({
  children,
  className,
  ariaLabel,
}: {
  children: React.ReactNode;
  className?: string;
  ariaLabel?: string;
}) {
  const ref = React.useRef<HTMLDivElement>(null);
  const [edges, setEdges] = React.useState({ left: false, right: false });

  const update = React.useCallback(() => {
    const el = ref.current;
    if (!el) return;
    // 1px of slack absorbs sub-pixel rounding so the arrow does not flicker
    // when the strip is scrolled fully to one end.
    setEdges({
      left: el.scrollLeft > 1,
      right: el.scrollLeft + el.clientWidth < el.scrollWidth - 1,
    });
  }, []);

  React.useEffect(() => {
    update();
    const el = ref.current;
    if (!el) return;
    const observer = new ResizeObserver(update);
    observer.observe(el);
    // Children changing width (e.g. a tab list rebuilt after data loads) also
    // changes overflow, and ResizeObserver on the scroller alone misses that.
    for (const child of Array.from(el.children)) observer.observe(child);
    return () => observer.disconnect();
  }, [update, children]);

  const scrollBy = (direction: -1 | 1) => {
    const el = ref.current;
    if (!el) return;
    el.scrollBy({ left: direction * Math.max(160, el.clientWidth * 0.6), behavior: "smooth" });
  };

  return (
    <div className={cn("relative", className)}>
      <div
        ref={ref}
        onScroll={update}
        aria-label={ariaLabel}
        className="scrollbar-none overflow-x-auto overscroll-x-contain"
      >
        {children}
      </div>

      {(["left", "right"] as const).map((side) => {
        const visible = edges[side];
        const Icon = side === "left" ? ChevronLeft : ChevronRight;
        return (
          <React.Fragment key={side}>
            <div
              aria-hidden="true"
              className={cn(
                "pointer-events-none absolute inset-y-0 w-12 transition-opacity duration-200",
                side === "left"
                  ? "left-0 bg-gradient-to-r from-background to-transparent"
                  : "right-0 bg-gradient-to-l from-background to-transparent",
                visible ? "opacity-100" : "opacity-0",
              )}
            />
            <button
              type="button"
              tabIndex={visible ? 0 : -1}
              aria-hidden={!visible}
              aria-label={`Scroll ${side}`}
              onClick={() => scrollBy(side === "left" ? -1 : 1)}
              className={cn(
                "absolute top-1/2 z-10 flex h-6 w-6 -translate-y-1/2 items-center justify-center rounded-full",
                "border border-hairline bg-surface-3 text-muted-foreground shadow-sm",
                "transition-opacity duration-200 hover:text-foreground",
                side === "left" ? "left-0" : "right-0",
                visible ? "opacity-100" : "pointer-events-none opacity-0",
              )}
            >
              <Icon className="h-3.5 w-3.5" />
            </button>
          </React.Fragment>
        );
      })}
    </div>
  );
}
