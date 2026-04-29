import { useEffect, useState } from 'react';
import { Search, X } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';

interface SearchInputProps {
  value?: string;
  onChange: (value: string) => void;
  placeholder?: string;
  debounceMs?: number;
  className?: string;
}

export function SearchInput({ value: controlledValue, onChange, placeholder = 'Search...', debounceMs = 300, className }: SearchInputProps) {
  const [local, setLocal] = useState(controlledValue || '');

  useEffect(() => {
    const t = setTimeout(() => onChange(local), debounceMs);
    return () => clearTimeout(t);
  }, [local, debounceMs, onChange]);

  useEffect(() => {
    if (controlledValue !== undefined) setLocal(controlledValue);
  }, [controlledValue]);

  return (
    <div className={cn('relative', className)}>
      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
      <Input
        value={local}
        onChange={e => setLocal(e.target.value)}
        placeholder={placeholder}
        className="pl-9 pr-8 bg-secondary/50 border-border/50"
      />
      {local && (
        <button onClick={() => setLocal('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}
