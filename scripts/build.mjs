import { mkdir, copyFile, rm } from 'node:fs/promises';
await rm('dist/public', { recursive: true, force: true });
await mkdir('dist/public', { recursive: true });
for (const file of ['index.html', 'styles.css', 'app.js']) await copyFile(file, `dist/public/${file}`);
console.log('Frontend built in dist/public (only public assets are copied).');
