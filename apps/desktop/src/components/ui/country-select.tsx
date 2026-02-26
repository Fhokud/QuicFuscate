import { useState, useEffect, useRef, useCallback } from "react";
import { Popover, PopoverTrigger, PopoverContent } from "@heroui/react";
import { cn, countryCodeToFlag } from "@/lib/utils";
import { COUNTRY_OPTIONS } from "@/data/countries";

const NO_FLAG_KEY = "__NO_FLAG__";
const TYPEAHEAD_RESET_MS = 1400;

interface CountrySelectProps {
  value: string;
  onChange: (code: string) => void;
  className?: string;
  triggerClassName?: string;
}

export function CountrySelect({ value, onChange, className, triggerClassName }: CountrySelectProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [highlightedIndex, setHighlightedIndex] = useState(-1);
  const typeaheadBufferRef = useRef("");
  const typeaheadTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // All options: No Flag first, then countries
  const allOptions = [
    { code: NO_FLAG_KEY, name: "No Flag" },
    ...COUNTRY_OPTIONS,
  ];

  // Find current index based on value
  const currentIndex = value
    ? allOptions.findIndex((opt) => opt.code.toUpperCase() === value.toUpperCase())
    : 0;

  // Reset highlight when opening
  useEffect(() => {
    if (isOpen) {
      setHighlightedIndex(currentIndex >= 0 ? currentIndex : 0);
      typeaheadBufferRef.current = "";
    }
  }, [isOpen, currentIndex]);

  // Focus listbox and scroll highlighted item into view when opening
  useEffect(() => {
    if (!isOpen) return;
    
    // Focus the listbox after a short delay to ensure it's rendered
    const focusTimer = setTimeout(() => {
      if (listRef.current) {
        listRef.current.focus();
      }
    }, 10);

    return () => clearTimeout(focusTimer);
  }, [isOpen]);

  // Scroll highlighted item into view
  useEffect(() => {
    if (!isOpen || highlightedIndex < 0 || !listRef.current) return;
    const items = listRef.current.querySelectorAll("[data-option]");
    if (items[highlightedIndex]) {
      items[highlightedIndex].scrollIntoView({ block: "nearest" });
    }
  }, [isOpen, highlightedIndex]);

  const findMatchIndex = useCallback((query: string): number => {
    const q = query.trim().toLowerCase();
    if (!q) return -1;
    if ("no flag".startsWith(q)) return 0;
    const idx = COUNTRY_OPTIONS.findIndex(
      ({ code, name }) =>
        name.toLowerCase().startsWith(q) || code.toLowerCase().startsWith(q)
    );
    return idx >= 0 ? idx + 1 : -1; // +1 because No Flag is at index 0
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (!isOpen) return;

      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setHighlightedIndex((prev) =>
            prev < allOptions.length - 1 ? prev + 1 : prev
          );
          break;
        case "ArrowUp":
          e.preventDefault();
          setHighlightedIndex((prev) => (prev > 0 ? prev - 1 : prev));
          break;
        case "Enter":
        case " ":
          e.preventDefault();
          if (highlightedIndex >= 0 && highlightedIndex < allOptions.length) {
            const selected = allOptions[highlightedIndex];
            onChange(selected.code === NO_FLAG_KEY ? "" : selected.code.toUpperCase());
            setIsOpen(false);
          }
          break;
        case "Escape":
          e.preventDefault();
          setIsOpen(false);
          break;
        case "Backspace":
          e.preventDefault();
          typeaheadBufferRef.current = typeaheadBufferRef.current.slice(0, -1);
          if (typeaheadBufferRef.current) {
            const matchIdx = findMatchIndex(typeaheadBufferRef.current);
            if (matchIdx >= 0) setHighlightedIndex(matchIdx);
          }
          break;
        default:
          // Typeahead: letters only
          if (e.key.length === 1 && /[a-zA-Z]/.test(e.key)) {
            e.preventDefault();
            typeaheadBufferRef.current += e.key.toLowerCase();

            const matchIdx = findMatchIndex(typeaheadBufferRef.current);
            if (matchIdx >= 0) setHighlightedIndex(matchIdx);

            if (typeaheadTimerRef.current) {
              clearTimeout(typeaheadTimerRef.current);
            }
            typeaheadTimerRef.current = setTimeout(() => {
              typeaheadBufferRef.current = "";
              typeaheadTimerRef.current = null;
            }, TYPEAHEAD_RESET_MS);
          }
          break;
      }
    },
    [isOpen, highlightedIndex, allOptions, onChange, findMatchIndex]
  );

  // Cleanup timer on unmount
  useEffect(() => {
    return () => {
      if (typeaheadTimerRef.current) {
        clearTimeout(typeaheadTimerRef.current);
      }
    };
  }, []);

  // Global keydown listener when popover is open - handles typeahead directly
  useEffect(() => {
    if (!isOpen) return;

    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          e.stopPropagation();
          setHighlightedIndex((prev) =>
            prev < allOptions.length - 1 ? prev + 1 : prev
          );
          break;
        case "ArrowUp":
          e.preventDefault();
          e.stopPropagation();
          setHighlightedIndex((prev) => (prev > 0 ? prev - 1 : prev));
          break;
        case "Enter":
        case " ":
          e.preventDefault();
          e.stopPropagation();
          setHighlightedIndex((currentIdx) => {
            if (currentIdx >= 0 && currentIdx < allOptions.length) {
              const selected = allOptions[currentIdx];
              onChange(selected.code === NO_FLAG_KEY ? "" : selected.code.toUpperCase());
              setIsOpen(false);
            }
            return currentIdx;
          });
          break;
        case "Escape":
          e.preventDefault();
          e.stopPropagation();
          setIsOpen(false);
          break;
        case "Backspace":
          e.preventDefault();
          e.stopPropagation();
          typeaheadBufferRef.current = typeaheadBufferRef.current.slice(0, -1);
          if (typeaheadBufferRef.current) {
            const matchIdx = findMatchIndex(typeaheadBufferRef.current);
            if (matchIdx >= 0) setHighlightedIndex(matchIdx);
          }
          break;
        default:
          // Typeahead: letters only
          if (e.key.length === 1 && /[a-zA-Z]/.test(e.key)) {
            e.preventDefault();
            e.stopPropagation();
            
            // Accumulate buffer
            typeaheadBufferRef.current += e.key.toLowerCase();

            const matchIdx = findMatchIndex(typeaheadBufferRef.current);
            if (matchIdx >= 0) setHighlightedIndex(matchIdx);

            // Reset timer
            if (typeaheadTimerRef.current) {
              clearTimeout(typeaheadTimerRef.current);
            }
            typeaheadTimerRef.current = setTimeout(() => {
              typeaheadBufferRef.current = "";
              typeaheadTimerRef.current = null;
            }, TYPEAHEAD_RESET_MS);
          }
          break;
      }
    };

    window.addEventListener("keydown", handleGlobalKeyDown, true);
    return () => window.removeEventListener("keydown", handleGlobalKeyDown, true);
  }, [isOpen, allOptions, onChange, findMatchIndex]);

  const handleSelect = (opt: { code: string; name: string }) => {
    onChange(opt.code === NO_FLAG_KEY ? "" : opt.code.toUpperCase());
    setIsOpen(false);
  };

  const displayValue = value ? countryCodeToFlag(value.toUpperCase()) : "-";

  return (
    <Popover
      isOpen={isOpen}
      onOpenChange={setIsOpen}
      placement="bottom-end"
      offset={6}
      shouldFlip={false}
      classNames={{
        base: "country-select-popover-base",
        content: "country-select-popover p-0 rounded-lg",
      }}
    >
      <PopoverTrigger>
        <button
          type="button"
          onKeyDown={handleKeyDown}
          className={cn(
            "h-8 min-h-8 w-[64px] px-0 rounded-md flex items-center justify-center",
            "glass-nav-pill glass-select-edge",
            "text-[14px] leading-none cursor-pointer",
            "focus:outline-none focus:ring-0",
            className,
            triggerClassName
          )}
          aria-haspopup="listbox"
          aria-expanded={isOpen}
        >
          <span className={value ? "" : "text-black/48"}>{displayValue}</span>
        </button>
      </PopoverTrigger>
      <PopoverContent>
        <div
          ref={listRef}
          role="listbox"
          className="max-h-[320px] overflow-y-auto p-1 outline-none"
          onKeyDown={handleKeyDown}
          tabIndex={0}
        >
          {allOptions.map((opt, idx) => {
            const isHighlighted = idx === highlightedIndex;
            const isSelected =
              (opt.code === NO_FLAG_KEY && !value) ||
              (opt.code !== NO_FLAG_KEY && opt.code.toUpperCase() === value.toUpperCase());

            return (
              <div
                key={opt.code}
                data-option
                role="option"
                aria-selected={isSelected}
                onClick={() => handleSelect(opt)}
                onMouseEnter={() => setHighlightedIndex(idx)}
                className={cn(
                  "flex items-center gap-2.5 px-2.5 py-1.5 rounded-md cursor-pointer transition-colors",
                  "text-[11px] text-black/90",
                  isHighlighted && "bg-accent/10",
                  isSelected && "bg-accent/20 font-semibold text-accent"
                )}
              >
                <span className="text-[14px] leading-none w-[18px] flex-shrink-0 text-center">
                  {opt.code === NO_FLAG_KEY ? "-" : countryCodeToFlag(opt.code)}
                </span>
                <span className="whitespace-nowrap">{opt.name}</span>
              </div>
            );
          })}
        </div>
      </PopoverContent>
    </Popover>
  );
}
