import { useEffect, useState, useCallback } from 'react';

export function usePolling<T>(fetcher: () => Promise<T>, interval = 30000) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setData(await fetcher());
    } catch (e) {
      console.error('Poll error:', e);
    } finally {
      setLoading(false);
    }
  }, [fetcher]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, interval);
    return () => clearInterval(id);
  }, [refresh, interval]);

  return { data, loading, refresh };
}
