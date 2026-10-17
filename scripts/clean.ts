// Removes build output so stale files from renamed modules never ship.
import { rmSync } from 'node:fs';

rmSync(new URL('../dist', import.meta.url), { recursive: true, force: true });
