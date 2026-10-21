import React, { useEffect, useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert,
  Search,
  Copy,
  Check,
  FolderOpen,
  ShieldCheck,
  Activity,
  RefreshCw,
  Terminal,
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface ContextMenuItem {
  label: string;
  icon?: React.ReactNode;
  shortcut?: string;
  danger?: boolean;
  action: () => void;
}

interface ContextMenuContextType {
  showMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void;
  hideMenu: () => void;
}

export const ContextMenuContext = React.createContext<ContextMenuContextType>({
  showMenu: () => {},
  hideMenu: () => {},
});

export const useContextMenu = () => React.useContext(ContextMenuContext);

export const ContextMenuProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [items, setItems] = useState<ContextMenuItem[]>([]);
  const menuRef = useRef<HTMLDivElement>(null);

  const showMenu = (e: React.MouseEvent, menuItems: ContextMenuItem[]) => {
    e.preventDefault();
    e.stopPropagation();

    // Clamp coordinates to screen boundaries
    const x = Math.min(e.clientX, window.innerWidth - 240);
    const y = Math.min(e.clientY, window.innerHeight - 300);

    setPosition({ x, y });
    setItems(menuItems);
    setIsOpen(true);
  };

  const hideMenu = () => {
    setIsOpen(false);
  };

  useEffect(() => {
    const handleGlobalClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        hideMenu();
      }
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        hideMenu();
      }
    };

    window.addEventListener("click", handleGlobalClick);
    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("scroll", hideMenu, true);

    return () => {
      window.removeEventListener("click", handleGlobalClick);
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("scroll", hideMenu, true);
    };
  }, []);

  return (
    <ContextMenuContext.Provider value={{ showMenu, hideMenu }}>
      {children}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            ref={menuRef}
            initial={{ opacity: 0, scale: 0.95, y: -4 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: -4 }}
            transition={{ duration: 0.12, ease: "easeOut" }}
            style={{
              position: "fixed",
              top: position.y,
              left: position.x,
              zIndex: 9999,
            }}
            className="w-56 rounded-xl border border-[#232738] bg-[#0E1017]/95 p-1.5 shadow-[0_16px_36px_rgba(0,0,0,0.6)] backdrop-blur-md"
          >
            <div className="flex flex-col gap-0.5">
              {items.map((item, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    item.action();
                    hideMenu();
                  }}
                  className={cn(
                    "flex w-full items-center justify-between rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors active:scale-[0.98]",
                    item.danger
                      ? "text-red-400 hover:bg-red-500/15 hover:text-red-300"
                      : "text-slate-300 hover:bg-[#1A1E2B] hover:text-white"
                  )}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">{item.icon}</span>
                    <span>{item.label}</span>
                  </div>
                  {item.shortcut && (
                    <span className="font-mono text-[10px] text-slate-500">
                      {item.shortcut}
                    </span>
                  )}
                </button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </ContextMenuContext.Provider>
  );
};
