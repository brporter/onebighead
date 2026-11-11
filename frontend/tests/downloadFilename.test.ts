import { expect, it } from 'vitest';
import { downloadFilename } from '../src/utils/downloadFilename';

it.each([
  [null, 'export.zip'],
  ['', 'export.zip'],
  ['attachment', 'export.zip'],
  ['attachment; filename=books.zip', 'books.zip'],
  ['attachment; filename="books.zip"', 'books.zip'],
  ['attachment; filename=books.zip; filename*=UTF-8\'\'books.zip', 'books.zip'],
  ['attachment; filename="Books; 2026.zip"; size=100', 'Books; 2026.zip'],
  ['attachment; FILENAME = books.zip  ; size=100', 'books.zip'],
  ['attachment; filename="Books \\"best\\".zip"', 'Books "best".zip'],
  ['attachment; filename="fallback.zip"; filename*=UTF-8\'en\'caf%C3%A9.zip', 'café.zip'],
  ['attachment; filename*=UTF-8\'\'bad%FF; filename="fallback.zip"', 'fallback.zip'],
  ['attachment; filename*=UTF-8\'\'bad%FF', 'export.zip'],
  ['attachment; filename*=UTF-8\'\'; filename=backup.zip', 'backup.zip'],
  ['attachment; filename=""', 'export.zip'],
  ['attachment; filename=   ', 'export.zip'],
])('reads the download name from %s', (header, expected) => {
  expect(downloadFilename(header, 'export.zip')).toBe(expected);
});
