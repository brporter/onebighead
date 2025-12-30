import type { Item } from '../types';

const items = [
  {
    id: 1,
    tenantId: 1,
    categoryId: 2,
    name: 'Macintosh Plus',
    description: 'A description of this item that may be many sentences long and includes paragraphs, formatted with Markdown.',
    summary: 'The Macintosh Plus is a personal computer designed, manufactured, and sold by Apple Computer, Inc. from January 16, 1986, to October 15, 1990.',
    properties: [
      { category: 'General', name: 'Release Date', value: '02/01/1986' },
      { category: 'General', name: 'Original Price', value: '$2999' },
    ],
    images: [
      { url: 'https://upload.wikimedia.org/wikipedia/commons/thumb/5/5b/Apple_Macintosh_Plus_white_background_%28cropped%29.jpg/2560px-Apple_Macintosh_Plus_white_background_%28cropped%29.jpg', alt: 'Macintosh Plus front view' },
      { url: 'https://upload.wikimedia.org/wikipedia/commons/thumb/f/f5/Apple-Macintosh.jpg/1280px-Apple-Macintosh.jpg', alt: 'Macintosh Plus back view' },
    ]
  },
  {
    id: 2,
    tenantId: 1,
    categoryId: 2,
    name: 'Macintosh Classic',
    description: 'A description of this item that may be many sentences long and includes paragraphs, formatted with Markdown.',
    summary: 'The Macintosh Classic is a personal computer designed, manufactured, and sold by Apple Computer, Inc. from October 15, 1990, to September 15, 1992.',
    properties: [
      { category: 'General', name: 'Release Date', value: '02/01/1988' },
      { category: 'General', name: 'Original Price', value: '$2999' },
      { category: 'Hardware', name: 'CPU', value: 'Motorola 68030' },
    ],
    images: [
      { url: 'https://upload.wikimedia.org/wikipedia/commons/d/d8/Macintosh_classic.jpg', alt: 'Macintosh Classic front view' },
      { url: 'https://upload.wikimedia.org/wikipedia/commons/3/37/Apple_Keyboard_II.jpg', alt: 'Macintosh Classic back view' },
    ]
  },
] as const satisfies readonly Item[];

export default items;

