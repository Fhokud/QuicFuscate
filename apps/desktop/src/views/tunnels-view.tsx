import { TunnelList } from "@/components/tunnel/tunnel-list";

export function TunnelsView() {
  return (
    <div className="flex flex-1 h-full min-h-0 overflow-x-hidden">
      <div className="flex flex-col flex-1 min-h-0 pl-1">
        <TunnelList />
      </div>
    </div>
  );
}
