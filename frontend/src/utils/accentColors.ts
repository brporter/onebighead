export interface AccentColor {
  start: string;
  end: string;
  name: string;
}

export const DEFAULT_PALETTE: AccentColor[] = [
  { start: '#c77d4a', end: '#d4a574', name: 'Warm copper' },
  { start: '#6b8f71', end: '#8baf91', name: 'Sage green' },
  { start: '#7a8ca8', end: '#9aacbf', name: 'Dusty blue' },
  { start: '#b8926a', end: '#c8a67e', name: 'Golden tan' },
  { start: '#9a7ea8', end: '#b098be', name: 'Muted plum' },
  { start: '#a88c7e', end: '#b8a090', name: 'Warm taupe' },
  { start: '#8a9a6b', end: '#a0b085', name: 'Olive' },
  { start: '#c4847a', end: '#d4a098', name: 'Dusty rose' },
];

export function getAccentColor(index: number, palette: AccentColor[] = DEFAULT_PALETTE): AccentColor {
  return palette[index % palette.length];
}
