// One reviewed source string, embedded verbatim in the pinned manifest commands.
export const DIRECTIO_FILESYSTEM = `// Embedded verbatim in both manifest commands: pinned runtime needs no new image.
import { lstatSync, openSync, fstatSync, readdirSync, mkdirSync, fchownSync, fsyncSync, closeSync, unlinkSync, constants } from 'node:fs';
const directoryName = 'perf-directio-20261006a', fileName = 'probe.bin';
const same = (a, b) => a && b && a.dev === b.dev && a.ino === b.ino;
const fail = () => { throw new Error('DIRECTIO_PATH_REJECTED'); };
const absent = (path) => lstatSync(path, {throwIfNoEntry:false});
function openDirectory(root, create, metadataOnly = false) {
  const before = lstatSync(root);
  if (!before.isDirectory() || before.isSymbolicLink()) fail();
  const parent = openSync(root, constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW);
  let directory;
  try {
    if (!same(before, fstatSync(parent))) fail();
    const path = \`/proc/self/fd/\${parent}/\${directoryName}\`;
    let prior = absent(path), created = false;
    if (!prior && create) { mkdirSync(path, {mode:0o700}); prior = lstatSync(path); created = true; }
    if (!prior || !prior.isDirectory() || prior.isSymbolicLink()) fail();
    directory = openSync(path, (metadataOnly && !created ? 0x200000 : constants.O_RDONLY)|constants.O_DIRECTORY|constants.O_NOFOLLOW);
    if (!same(prior, fstatSync(directory))) fail();
    // Set ownership only on this newly created original directory; never repair.
    if (created) { fchownSync(directory, 10001, 10001); fsyncSync(parent); }
    const stat = fstatSync(directory);
    if (stat.uid !== 10001 || stat.gid !== 10001 || (stat.mode & 0o777) !== 0o700) fail();
    const check = () => {
      if (!same(before, lstatSync(root)) || !same(stat, absent(path))) fail();
    };
    check();
    return {parent, directory, check, file:\`/proc/self/fd/\${directory}/\${fileName}\`};
  } catch (error) { if (directory !== undefined) closeSync(directory); closeSync(parent); throw error; }
}
function ownedFile(stat) {
  if (!stat || !stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== 10001 || stat.gid !== 10001) fail();
  // Normal dd output, including 0644, is valid; ownership/type/link checks suffice.
}
function removeKnown(handle, expected) {
  handle.check();
  const stat = lstatSync(handle.file); ownedFile(stat);
  if (!same(stat, expected)) fail();
  const fd = openSync(handle.file, constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try {
    ownedFile(fstatSync(fd));
    if (!same(stat, fstatSync(fd))) fail();
    handle.check();
    const fresh = lstatSync(handle.file); ownedFile(fresh);
    if (!same(fresh, stat)) fail();
    unlinkSync(handle.file); fsyncSync(handle.directory);
    if (absent(handle.file)) fail();
  } finally { closeSync(fd); }
}
function initialize(root) {
  const handle = openDirectory(root, true);
  try {
    const entries = readdirSync(\`/proc/self/fd/\${handle.directory}\`);
    if (entries.length > 1 || entries.some((name) => name !== fileName)) fail();
    if (entries.length) { const stat = lstatSync(handle.file); ownedFile(stat); removeKnown(handle, stat); console.log('SYNTHETIC_REMOVED'); }
    handle.check();
    if (readdirSync(\`/proc/self/fd/\${handle.directory}\`).length || absent(handle.file)) fail();
    console.log('SYNTHETIC_ABSENT');
  } finally { closeSync(handle.directory); closeSync(handle.parent); }
}
`;
