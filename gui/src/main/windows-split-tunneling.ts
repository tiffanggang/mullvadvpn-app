import { app, shell } from 'electron';
import fs from 'fs';
import path from 'path';
import { IApplication } from '../shared/application-types';
import log from '../shared/logging';
import {
  ArrayValue,
  DOS_HEADER,
  IMAGE_DATA_DIRECTORY,
  IMAGE_DIRECTORY_ENTRY_IMPORT,
  IMAGE_FILE_HEADER,
  IMAGE_IMPORT_MODULE_DIRECTORY,
  IMAGE_NT_HEADERS,
  IMAGE_NT_HEADERS64,
  ImageNtHeadersUnion,
  IMAGE_OPTIONAL_HEADER32,
  ImageOptionalHeaderUnion,
  PrimitiveValue,
  rvaToOffset,
  StructValue,
  Value,
} from './windows-pe-parser';

const APPLICATION_PATHS = [
  `${process.env.ProgramData}/Microsoft/Windows/Start Menu/Programs`,
  `${process.env.AppData}/Microsoft/Windows/Start Menu/Programs`,
];

interface ShortcutDetails {
  target: string;
  name: string;
  args?: string;
}

const APPLICATION_ALLOW_LIST = ['firefox.exe', 'chrome.exe'];

const shortcutCache: { [path: string]: ShortcutDetails } = {};
const applicationCache: { [path: string]: IApplication } = {};

// Finds applications by searching through the startmenu for shortcuts with and exe-file as target.
export async function getApplications(options: {
  applicationPaths?: string[];
  noCache?: boolean;
}): Promise<{ fromCache: boolean; applications: IApplication[] }> {
  if (
    !options.noCache &&
    (Object.keys(applicationCache).length === 0 || Object.keys(shortcutCache).length === 0)
  ) {
    return getApplications({ ...options, noCache: true });
  }

  if (options.noCache) {
    await updateShortcutCache();
  }

  if (options.applicationPaths) {
    options.applicationPaths.forEach(addApplicationPathToShortcutCache);
  }

  const applications = await getApplicationsImpl(options.applicationPaths);
  return {
    fromCache: !options.noCache,
    applications,
  };
}

async function getApplicationsImpl(applicationPaths?: string[]): Promise<IApplication[]> {
  const shortcuts = Object.values(shortcutCache)
    .filter(
      (shortcut) => applicationPaths === undefined || applicationPaths.includes(shortcut.target),
    )
    .sort((a, b) => a.name.localeCompare(b.name));

  return Promise.all(
    shortcuts.map(async (shortcut) => {
      if (applicationCache[shortcut.target] === undefined) {
        applicationCache[shortcut.target] = await convertToSplitTunnelingApplication(shortcut);
      }

      return applicationCache[shortcut.target];
    }),
  );
}

async function updateShortcutCache(): Promise<void> {
  const links = await Promise.all(APPLICATION_PATHS.map(findAllLinks));
  const resolvedLinks = removeDuplicates(resolveLinks(links.flat()));

  const shortcuts: ShortcutDetails[] = [];
  for (const shortcut of resolvedLinks) {
    if (
      APPLICATION_ALLOW_LIST.includes(path.basename(shortcut.target)) ||
      (await importsDll(shortcut.target, 'WS2_32.dll'))
    ) {
      shortcuts.push(shortcut);
      shortcutCache[shortcut.target] = shortcut;
    }
  }
}

function addApplicationPathToShortcutCache(applicationPath: string): void {
  if (shortcutCache[applicationPath] === undefined) {
    shortcutCache[applicationPath] = {
      target: applicationPath,
      name: path.basename(applicationPath),
    };
  }
}

async function findAllLinks(path: string): Promise<string[]> {
  if (path.endsWith('.lnk')) {
    return [path];
  } else {
    const stat = await fs.promises.stat(path);
    if (stat.isDirectory()) {
      const contents = await fs.promises.readdir(path);
      const result = await Promise.all(contents.map((item) => findAllLinks(`${path}/${item}`)));
      return result.flat();
    } else {
      return [];
    }
  }
}

function resolveLinks(linkPaths: string[]): ShortcutDetails[] {
  return linkPaths
    .map((link) => {
      try {
        return {
          ...shell.readShortcutLink(path.resolve(link)),
          name: path.parse(link).name,
        };
      } catch (_e) {
        return null;
      }
    })
    .filter(
      (shortcut): shortcut is ShortcutDetails =>
        shortcut !== null &&
        shortcut.name !== 'Mullvad VPN' &&
        shortcut.target.endsWith('.exe') &&
        !shortcut.target.toLowerCase().includes('uninstall') &&
        !shortcut.name.toLowerCase().includes('uninstall'),
    );
}

function removeDuplicates(shortcuts: ShortcutDetails[]): ShortcutDetails[] {
  const unique = shortcuts.reduce((shortcuts, shortcut) => {
    if (shortcuts[shortcut.target]) {
      if (
        shortcuts[shortcut.target].args &&
        shortcuts[shortcut.target].args !== '' &&
        (!shortcut.args || shortcut.args === '')
      ) {
        shortcuts[shortcut.target] = shortcut;
      }
    } else {
      shortcuts[shortcut.target] = shortcut;
    }
    return shortcuts;
  }, {} as Record<string, ShortcutDetails>);

  return Object.values(unique);
}

async function convertToSplitTunnelingApplication(
  shortcut: ShortcutDetails,
): Promise<IApplication> {
  return {
    absolutepath: shortcut.target,
    name: shortcut.name,
    icon: await retrieveIcon(shortcut.target),
  };
}

async function retrieveIcon(exe: string) {
  const icon = await app.getFileIcon(exe);
  return icon.toDataURL();
}

async function importsDll(path: string, dllName: string): Promise<boolean> {
  let fileHandle: fs.promises.FileHandle;
  try {
    fileHandle = await fs.promises.open(path, fs.constants.O_RDONLY);
  } catch (e) {
    log.error('Failed to create file handle.', e);
    return false;
  }

  const imports = await getExeImports(fileHandle, path);
  await fileHandle.close();
  return imports.map((name) => name.toLowerCase()).includes(dllName.toLowerCase());
}

async function getExeImports(fileHandle: fs.promises.FileHandle, path: string): Promise<string[]> {
  try {
    const ntHeader = await getNtHeader(fileHandle);
    const optionalHeader = ntHeader.get<StructValue<ImageOptionalHeaderUnion>>('OptionalHeader');

    const importSectionRva = optionalHeader
      .get<ArrayValue<typeof IMAGE_DATA_DIRECTORY>>('DataDirectory')
      .nth(IMAGE_DIRECTORY_ENTRY_IMPORT)
      .get('VirtualAddress')
      .value();

    if (importSectionRva === 0x0) {
      return [];
    }

    const numberOfSections = ntHeader
      .get<StructValue<typeof IMAGE_FILE_HEADER>>('FileHeader')
      .get<PrimitiveValue>('NumberOfSections')
      .value<number>();

    const importSectionOffset = await rvaToOffset(
      fileHandle,
      importSectionRva,
      numberOfSections,
      ntHeader.endOffset,
    );

    const moduleNames = await getImportModuleNames(
      fileHandle,
      importSectionOffset,
      ntHeader.endOffset,
      numberOfSections,
    );

    return moduleNames;
  } catch (e) {
    log.error(`Failed to read .exe import table for ${path}.`, e);
    return [];
  }
}

async function readString(
  fileHandle: fs.promises.FileHandle,
  offset: number,
  buffer = Buffer.alloc(1000),
  index = 0,
): Promise<string> {
  await fileHandle.read(buffer, index, 1, offset + index);
  if (buffer[index] === 0x0) {
    return buffer.slice(0, index).toString('ascii');
  } else {
    return readString(fileHandle, offset, buffer, index + 1);
  }
}

async function getNtHeader(
  fileHandle: fs.promises.FileHandle,
): Promise<StructValue<ImageNtHeadersUnion>> {
  const dosHeader = await Value.fromFile(fileHandle, 0, DOS_HEADER);
  const eMagic = dosHeader.get<PrimitiveValue>('e_magic').value<number>();
  if (eMagic !== 0x5a4d) {
    throw new Error('Incorrect PE format');
  }

  const ntHeaderOffset = dosHeader.get<PrimitiveValue>('e_lfanew').value<number>();

  const ntHeader32 = await Value.fromFile(fileHandle, ntHeaderOffset, IMAGE_NT_HEADERS);
  const magic = ntHeader32
    .get<StructValue<typeof IMAGE_OPTIONAL_HEADER32>>('OptionalHeader')
    .get<PrimitiveValue>('Magic')
    .value<number>();

  return magic === 0x20b
    ? Value.fromFile(fileHandle, ntHeaderOffset, IMAGE_NT_HEADERS64)
    : ntHeader32;
}

async function getImportModuleNames(
  fileHandle: fs.promises.FileHandle,
  importSectionOffset: number,
  firstSectionAddress: number,
  numberOfSections: number,
): Promise<string[]> {
  const moduleNames: string[] = [];
  const entrySize = Value.sizeOf(IMAGE_IMPORT_MODULE_DIRECTORY);

  // eslint-disable-next-line no-constant-condition
  for (let i = 0; true; i++) {
    const importEntry = await Value.fromFile(
      fileHandle,
      importSectionOffset + i * entrySize,
      IMAGE_IMPORT_MODULE_DIRECTORY,
    );
    const nameRva = importEntry.get('ModuleName').value();

    if (nameRva !== 0x0) {
      const offset = await rvaToOffset(fileHandle, nameRva, numberOfSections, firstSectionAddress);

      const name = await readString(fileHandle, offset);
      moduleNames.push(name);
    } else {
      return moduleNames;
    }
  }
}
