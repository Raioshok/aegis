import { useEffect, useRef } from "react";
import gsap from "gsap";
import { useGSAP } from "@gsap/react";

// Register the useGSAP plugin globally
gsap.registerPlugin(useGSAP);

/**
 * Staggers in semantic element groups with opacity, subtle translateY, and blur.
 * Follows make-interfaces-feel-better Rule 5: Infrequent staged entrance with ~60-80ms stagger.
 */
export function useStaggerEnter(
  containerRef: React.RefObject<HTMLElement | null>,
  targetSelector: string = ".stagger-item",
  dependencies: any[] = []
) {
  useGSAP(
    () => {
      if (!containerRef.current) return;
      const elements = containerRef.current.querySelectorAll(targetSelector);
      if (elements.length === 0) return;

      gsap.fromTo(
        elements,
        {
          opacity: 0,
          y: 8,
          filter: "blur(4px)",
        },
        {
          opacity: 1,
          y: 0,
          filter: "blur(0px)",
          duration: 0.35,
          stagger: 0.06,
          ease: "power2.out",
          clearProps: "all",
        }
      );
    },
    { scope: containerRef, dependencies, revertOnUpdate: true }
  );
}

/**
 * Animate numbers smoothly from current to target with zero layout shift (tabular-nums).
 */
export function useCounterTween(
  targetValue: number,
  formatFn: (v: number) => string = (v) => Math.round(v).toString()
) {
  const nodeRef = useRef<HTMLSpanElement | null>(null);
  const currentValRef = useRef(0);

  useEffect(() => {
    const node = nodeRef.current;
    if (!node) return;

    const proxy = { val: currentValRef.current };
    const tween = gsap.to(proxy, {
      val: targetValue,
      duration: 0.5,
      ease: "power1.out",
      onUpdate: () => {
        if (nodeRef.current) {
          nodeRef.current.textContent = formatFn(proxy.val);
        }
      },
      onComplete: () => {
        currentValRef.current = targetValue;
      },
    });

    return () => {
      tween.kill();
    };
  }, [targetValue, formatFn]);

  return nodeRef;
}

export { gsap, useGSAP };
