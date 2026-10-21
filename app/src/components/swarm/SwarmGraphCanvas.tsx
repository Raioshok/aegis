import React, { useRef, useEffect, useState, useMemo } from "react";
import { type ProcessItem, type ProcessTreeNodeDto } from "@/lib/api";
import { useContextMenu } from "@/components/reactbits";
import {
  Bot,
  ShieldAlert,
  Play,
  Pause,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Terminal,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface SwarmNode {
  id: number; // pid
  name: string;
  exe: string;
  cmdline: string;
  risk_score: number;
  is_agent: boolean;
  agent_label?: string;
  mitre: string[];
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  color: string;
}

interface SwarmLink {
  source: number; // ppid
  target: number; // pid
}

interface SwarmGraphProps {
  nodesData: ProcessItem[];
  treesData: ProcessTreeNodeDto[];
  selectedPid: number | null;
  onSelectPid: (pid: number) => void;
  onKillPid?: (pid: number) => void;
}

export const SwarmGraphCanvas: React.FC<SwarmGraphProps> = ({
  nodesData,
  treesData,
  selectedPid,
  onSelectPid,
  onKillPid,
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { showMenu } = useContextMenu();

  const [isRunning, setIsRunning] = useState<boolean>(true);
  const [filterMode, setFilterMode] = useState<"all" | "agents" | "threats">("all");
  const [zoom, setZoom] = useState<number>(1.0);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [draggedNode, setDraggedNode] = useState<SwarmNode | null>(null);
  const isPanningRef = useRef<boolean>(false);
  const lastMousePosRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });

  // Transform process data into physics graph
  const { initialNodes, initialLinks } = useMemo(() => {
    const nodes: SwarmNode[] = [];
    const links: SwarmLink[] = [];
    const pidSet = new Set<number>();

    // Flatten tree structure to build links
    const traverse = (item: ProcessTreeNodeDto, ppid?: number) => {
      pidSet.add(item.pid);
      if (ppid !== undefined) {
        links.push({ source: ppid, target: item.pid });
      }

      const isHighRisk = item.risk_score >= 70;
      const isMediumRisk = item.risk_score >= 35 && item.risk_score < 70;
      
      let color = "#10B981"; // Emerald
      if (item.is_agent_context) {
        color = "#8B5CF6"; // Violet
      } else if (isHighRisk) {
        color = "#EF4444"; // Crimson
      } else if (isMediumRisk) {
        color = "#F59E0B"; // Amber
      }

      const radius = item.is_agent_context ? 22 : isHighRisk ? 20 : 15;

      nodes.push({
        id: item.pid,
        name: item.name,
        exe: item.name,
        cmdline: item.name,
        risk_score: item.risk_score,
        is_agent: item.is_agent_context ?? false,
        agent_label: item.agent_type_label ?? undefined,
        mitre: item.mitre_techniques ?? [],
        x: (Math.random() - 0.5) * 600,
        y: (Math.random() - 0.5) * 450,
        vx: 0,
        vy: 0,
        radius,
        color,
      });

      if (item.children) {
        item.children.forEach((c) => traverse(c, item.pid));
      }
    };

    treesData.forEach((t) => traverse(t));

    // Fallback if tree is empty, populate from nodesData
    if (nodes.length === 0 && nodesData.length > 0) {
      nodesData.slice(0, 40).forEach((p) => {
        nodes.push({
          id: p.pid,
          name: p.name,
          exe: p.path,
          cmdline: p.name,
          risk_score: p.risk_score ?? 10,
          is_agent: p.is_agent_context ?? false,
          agent_label: p.agent_label ?? undefined,
          mitre: p.mitre_techniques ?? [],
          x: (Math.random() - 0.5) * 600,
          y: (Math.random() - 0.5) * 450,
          vx: 0,
          vy: 0,
          radius: p.is_agent_context ? 22 : 15,
          color: p.is_agent_context ? "#8B5CF6" : "#10B981",
        });
      });
    }

    return { initialNodes: nodes, initialLinks: links };
  }, [nodesData, treesData]);

  const nodesRef = useRef<SwarmNode[]>([]);
  const linksRef = useRef<SwarmLink[]>([]);

  useEffect(() => {
    nodesRef.current = initialNodes;
    linksRef.current = initialLinks;
  }, [initialNodes, initialLinks]);

  // Physics animation loop
  useEffect(() => {
    let animationFrameId: number;

    const simulate = () => {
      const nodes = nodesRef.current;
      const links = linksRef.current;

      if (isRunning && nodes.length > 0) {
        // 1. Coulomb repulsion between all nodes
        for (let i = 0; i < nodes.length; i++) {
          for (let j = i + 1; j < nodes.length; j++) {
            const dx = nodes[j].x - nodes[i].x;
            const dy = nodes[j].y - nodes[i].y;
            const distSq = dx * dx + dy * dy + 100;
            const dist = Math.sqrt(distSq);
            const force = 1800 / distSq;

            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;

            nodes[i].vx -= fx;
            nodes[i].vy -= fy;
            nodes[j].vx += fx;
            nodes[j].vy += fy;
          }
        }

        // 2. Hooke's attraction along links
        const nodeMap = new Map<number, SwarmNode>();
        nodes.forEach((n) => nodeMap.set(n.id, n));

        links.forEach((l) => {
          const src = nodeMap.get(l.source);
          const tgt = nodeMap.get(l.target);
          if (src && tgt) {
            const dx = tgt.x - src.x;
            const dy = tgt.y - src.y;
            const dist = Math.sqrt(dx * dx + dy * dy) + 0.1;
            const targetDist = 90;
            const force = (dist - targetDist) * 0.04;

            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;

            src.vx += fx;
            src.vy += fy;
            tgt.vx -= fx;
            tgt.vy -= fy;
          }
        });

        // 3. Centering gravity & damping
        nodes.forEach((n) => {
          if (draggedNode && draggedNode.id === n.id) {
            n.vx = 0;
            n.vy = 0;
            return;
          }

          n.vx += -n.x * 0.005;
          n.vy += -n.y * 0.005;

          n.vx *= 0.88;
          n.vy *= 0.88;

          n.x += n.vx;
          n.y += n.vy;
        });
      }

      // Render canvas frame
      const canvas = canvasRef.current;
      if (canvas) {
        const ctx = canvas.getContext("2d");
        if (ctx) {
          const w = canvas.width;
          const h = canvas.height;

          ctx.clearRect(0, 0, w, h);
          ctx.save();
          ctx.translate(w / 2 + pan.x, h / 2 + pan.y);
          ctx.scale(zoom, zoom);

          // Draw links
          const nodeMap = new Map<number, SwarmNode>();
          nodes.forEach((n) => nodeMap.set(n.id, n));

          ctx.lineWidth = 1.5;
          links.forEach((l) => {
            const src = nodeMap.get(l.source);
            const tgt = nodeMap.get(l.target);
            if (src && tgt) {
              const gradient = ctx.createLinearGradient(src.x, src.y, tgt.x, tgt.y);
              gradient.addColorStop(0, "rgba(71, 85, 105, 0.4)");
              gradient.addColorStop(1, "rgba(100, 116, 139, 0.2)");
              ctx.strokeStyle = gradient;

              ctx.beginPath();
              ctx.moveTo(src.x, src.y);
              ctx.lineTo(tgt.x, tgt.y);
              ctx.stroke();
            }
          });

          // Draw nodes
          nodes.forEach((n) => {
            if (filterMode === "agents" && !n.is_agent) return;
            if (filterMode === "threats" && n.risk_score < 35) return;

            const isSelected = selectedPid === n.id;

            // Halo for agents or high risk
            if (n.is_agent || n.risk_score >= 70 || isSelected) {
              ctx.beginPath();
              ctx.arc(n.x, n.y, n.radius + 8, 0, Math.PI * 2);
              ctx.fillStyle = isSelected
                ? "rgba(255, 114, 34, 0.25)"
                : n.is_agent
                ? "rgba(139, 92, 246, 0.2)"
                : "rgba(239, 68, 68, 0.25)";
              ctx.fill();
            }

            // Node Circle
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
            ctx.fillStyle = isSelected ? "#FF7222" : n.color;
            ctx.fill();

            ctx.lineWidth = isSelected ? 2.5 : 1.5;
            ctx.strokeStyle = isSelected ? "#FFFFFF" : "#1E2230";
            ctx.stroke();

            // Label text
            ctx.font = "bold 11px Inter, sans-serif";
            ctx.fillStyle = isSelected ? "#FFFFFF" : "#F1F5F9";
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillText(n.name.slice(0, 12), n.x, n.y + n.radius + 14);

            // PID Sub-label
            ctx.font = "9px monospace";
            ctx.fillStyle = "#94A3B8";
            ctx.fillText(`PID: ${n.id}`, n.x, n.y + n.radius + 25);
          });

          ctx.restore();
        }
      }

      animationFrameId = requestAnimationFrame(simulate);
    };

    animationFrameId = requestAnimationFrame(simulate);
    return () => cancelAnimationFrame(animationFrameId);
  }, [isRunning, zoom, pan, draggedNode, selectedPid, filterMode]);

  // Coordinate transformation from screen to graph space
  const screenToGraph = (clientX: number, clientY: number) => {
    if (!canvasRef.current) return { x: 0, y: 0 };
    const rect = canvasRef.current.getBoundingClientRect();
    const w = canvasRef.current.width;
    const h = canvasRef.current.height;

    const screenX = clientX - rect.left;
    const screenY = clientY - rect.top;

    const graphX = (screenX - (w / 2 + pan.x)) / zoom;
    const graphY = (screenY - (h / 2 + pan.y)) / zoom;

    return { x: graphX, y: graphY };
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    const { x, y } = screenToGraph(e.clientX, e.clientY);

    // Check if clicked a node
    const clicked = nodesRef.current.find((n) => {
      const dx = n.x - x;
      const dy = n.y - y;
      return Math.sqrt(dx * dx + dy * dy) <= n.radius + 5;
    });

    if (clicked) {
      onSelectPid(clicked.id);
      setDraggedNode(clicked);
    } else {
      isPanningRef.current = true;
      lastMousePosRef.current = { x: e.clientX, y: e.clientY };
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (draggedNode) {
      const { x, y } = screenToGraph(e.clientX, e.clientY);
      draggedNode.x = x;
      draggedNode.y = y;
    } else if (isPanningRef.current) {
      const dx = e.clientX - lastMousePosRef.current.x;
      const dy = e.clientY - lastMousePosRef.current.y;
      setPan((p) => ({ x: p.x + dx, y: p.y + dy }));
      lastMousePosRef.current = { x: e.clientX, y: e.clientY };
    }
  };

  const handleMouseUp = () => {
    setDraggedNode(null);
    isPanningRef.current = false;
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom((z) => Math.min(2.5, Math.max(0.4, z * delta)));
  };

  const handleContextMenu = (e: React.MouseEvent) => {
    const { x, y } = screenToGraph(e.clientX, e.clientY);

    const target = nodesRef.current.find((n) => {
      const dx = n.x - x;
      const dy = n.y - y;
      return Math.sqrt(dx * dx + dy * dy) <= n.radius + 5;
    });

    if (target) {
      showMenu(e, [
        {
          label: `Terminate ${target.name} (PID: ${target.id})`,
          danger: true,
          action: () => onKillPid?.(target.id),
        },
        {
          label: "Inspect Lineage & Shannon Entropy",
          action: () => onSelectPid(target.id),
        },
        {
          label: "Copy Command Line",
          action: () => navigator.clipboard.writeText(target.cmdline || target.name),
        },
      ]);
    } else {
      showMenu(e, [
        {
          label: isRunning ? "Pause Swarm Simulation" : "Resume Swarm Simulation",
          action: () => setIsRunning(!isRunning),
        },
        {
          label: "Reset Graph Camera (Fit View)",
          action: () => {
            setZoom(1.0);
            setPan({ x: 0, y: 0 });
          },
        },
      ]);
    }
  };

  return (
    <div
      ref={containerRef}
      className="relative w-full h-[540px] rounded-[18px] border border-[#1E2230] bg-[#0E1017] overflow-hidden select-none"
    >
      {/* Background Subtle Radar Grid */}
      <div className="absolute inset-0 pointer-events-none opacity-20 bg-[radial-gradient(#2A3042_1px,transparent_1px)] [background-size:24px_24px]" />

      {/* Floating Canvas Controls (Inspired by MiroFish & ReactBits) */}
      <div className="absolute top-4 left-4 z-20 flex items-center gap-2">
        <button
          onClick={() => setIsRunning(!isRunning)}
          className="flex items-center gap-1.5 rounded-lg border border-[#232738] bg-[#141721]/90 px-3 py-1.5 text-xs font-semibold text-slate-200 backdrop-blur-md hover:bg-[#1E2230] hover:text-white transition-all active:scale-95"
        >
          {isRunning ? <Pause size={13} /> : <Play size={13} />}
          <span>{isRunning ? "Pause Swarm" : "Resume"}</span>
        </button>

        <button
          onClick={() => {
            setZoom(1.0);
            setPan({ x: 0, y: 0 });
          }}
          className="p-1.5 rounded-lg border border-[#232738] bg-[#141721]/90 text-slate-300 backdrop-blur-md hover:bg-[#1E2230] hover:text-white transition-all active:scale-95"
          title="Reset Zoom & Pan"
        >
          <RotateCcw size={14} />
        </button>

        {/* Filter Pills */}
        <div className="flex items-center rounded-lg border border-[#232738] bg-[#141721]/90 p-0.5 text-[11px] font-medium backdrop-blur-md">
          <button
            onClick={() => setFilterMode("all")}
            className={cn(
              "px-2.5 py-1 rounded-md transition-colors",
              filterMode === "all" ? "bg-[#FF7222] text-white font-bold" : "text-slate-400 hover:text-white"
            )}
          >
            All Swarm ({nodesRef.current.length})
          </button>
          <button
            onClick={() => setFilterMode("agents")}
            className={cn(
              "flex items-center gap-1 px-2.5 py-1 rounded-md transition-colors",
              filterMode === "agents" ? "bg-purple-600 text-white font-bold" : "text-purple-400 hover:text-purple-300"
            )}
          >
            <Bot size={12} />
            AI Agents
          </button>
          <button
            onClick={() => setFilterMode("threats")}
            className={cn(
              "flex items-center gap-1 px-2.5 py-1 rounded-md transition-colors",
              filterMode === "threats" ? "bg-red-600 text-white font-bold" : "text-red-400 hover:text-red-300"
            )}
          >
            <ShieldAlert size={12} />
            High Risk
          </button>
        </div>
      </div>

      {/* Floating Zoom Controls (Bottom-Right) */}
      <div className="absolute bottom-4 right-4 z-20 flex items-center gap-1 rounded-lg border border-[#232738] bg-[#141721]/90 p-1 backdrop-blur-md">
        <button
          onClick={() => setZoom((z) => Math.min(2.5, z * 1.2))}
          className="p-1.5 rounded-md text-slate-300 hover:bg-[#1E2230] hover:text-white transition-all active:scale-95"
          title="Zoom In"
        >
          <ZoomIn size={14} />
        </button>
        <span className="px-1 text-[11px] font-mono text-slate-400">
          {Math.round(zoom * 100)}%
        </span>
        <button
          onClick={() => setZoom((z) => Math.max(0.4, z * 0.8))}
          className="p-1.5 rounded-md text-slate-300 hover:bg-[#1E2230] hover:text-white transition-all active:scale-95"
          title="Zoom Out"
        >
          <ZoomOut size={14} />
        </button>
      </div>

      {/* Main Interactive HTML5 Canvas */}
      <canvas
        ref={canvasRef}
        width={1080}
        height={540}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onWheel={handleWheel}
        onContextMenu={handleContextMenu}
        className="w-full h-full cursor-grab active:cursor-grabbing"
      />
    </div>
  );
};
