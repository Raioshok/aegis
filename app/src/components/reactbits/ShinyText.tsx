import React from "react";
import { cn } from "@/lib/utils";

interface ShinyTextProps {
  text: string;
  disabled?: boolean;
  speed?: number;
  className?: string;
}

export const ShinyText: React.FC<ShinyTextProps> = ({
  text,
  disabled = false,
  speed = 5,
  className = "",
}) => {
  const animationDuration = `${speed}s`;

  return (
    <span
      className={cn(
        "inline-block font-semibold bg-clip-text text-transparent",
        !disabled && "animate-shine bg-[linear-gradient(120deg,rgba(255,255,255,0.4)_0%,rgba(255,255,255,0.95)_50%,rgba(255,255,255,0.4)_100%)] [background-size:200%_100%]",
        className
      )}
      style={{
        animationDuration,
      }}
    >
      {text}
    </span>
  );
};
