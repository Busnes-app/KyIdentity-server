import type React from 'react';
import {
  Globe, Link, Mail, MessageSquare, Calendar, StickyNote, FileText, Book, Bookmark, Folder,
  Image, Camera, Video, Film, Music, Tv, Radio, Gamepad2, House, Users,
  Lock, Key, Shield, Server, Database, HardDrive, Cloud, Container, Network, Wifi, Cpu,
  Monitor, Terminal, Code, GitBranch, ChartLine, Activity, Printer, Download, Rss, Wrench, Bug, Clock, Map,
} from 'lucide-react';

export type LauncherIcon = React.FC<{ size?: number; className?: string }>;

/** Mirrors the server's launcherIcons allowlist; anything else is rejected at the API.
 *  Order is the picker's order. "favicon" is handled separately: it is a fetched image. */
export const LAUNCHER_ICONS: ReadonlyArray<[name: string, label: string, Icon: LauncherIcon]> = [
  ['globe', 'Website', Globe],
  ['link', 'Link', Link],
  ['mail', 'Mail', Mail],
  ['message-square', 'Chat', MessageSquare],
  ['calendar', 'Calendar', Calendar],
  ['sticky-note', 'Notes', StickyNote],
  ['file-text', 'Documents', FileText],
  ['book', 'Wiki', Book],
  ['bookmark', 'Bookmarks', Bookmark],
  ['folder', 'Files', Folder],
  ['image', 'Photos', Image],
  ['camera', 'Cameras', Camera],
  ['video', 'Video', Video],
  ['film', 'Movies', Film],
  ['music', 'Music', Music],
  ['tv', 'TV', Tv],
  ['radio', 'Radio', Radio],
  ['gamepad-2', 'Games', Gamepad2],
  ['house', 'Home', House],
  ['users', 'People', Users],
  ['lock', 'Passwords', Lock],
  ['key', 'Keys', Key],
  ['shield', 'Security', Shield],
  ['server', 'Server', Server],
  ['database', 'Database', Database],
  ['hard-drive', 'Storage', HardDrive],
  ['cloud', 'Cloud', Cloud],
  ['container', 'Containers', Container],
  ['network', 'Network', Network],
  ['wifi', 'Wi-Fi', Wifi],
  ['cpu', 'Hardware', Cpu],
  ['monitor', 'Desktop', Monitor],
  ['terminal', 'Terminal', Terminal],
  ['code', 'Code', Code],
  ['git-branch', 'Git', GitBranch],
  ['chart-line', 'Metrics', ChartLine],
  ['activity', 'Monitoring', Activity],
  ['printer', 'Printer', Printer],
  ['download', 'Downloads', Download],
  ['rss', 'Feeds', Rss],
  ['wrench', 'Tools', Wrench],
  ['bug', 'Issues', Bug],
  ['clock', 'Time', Clock],
  ['map', 'Maps', Map],
];

/** Mirrors the server's suiteIcons: bundled suite app icons, named "suite:<app>". */
export const SUITE_ICONS: ReadonlyArray<[app: string, label: string]> = [
  ['kycalendar', 'KyCalendar'],
  ['kydash', 'KyDash'],
  ['kydns', 'KyDNS'],
  ['kydrive', 'KyDrive'],
  ['kymessages', 'KyMessages'],
  ['kynotes', 'KyNotes'],
  ['kypost', 'KyPost'],
  ['kypulse', 'KyPulse'],
  ['kyrecovery', 'KyRecovery'],
  ['kyyard', 'KyYard'],
];

/** Same-origin URL of a bundled suite icon; only names on the list resolve. */
export function suiteIconUrl(iconName: string): string | undefined {
  const app = iconName.startsWith('suite:') ? iconName.slice(6) : '';
  return SUITE_ICONS.some(([a]) => a === app) ? `/suite-icons/${app}.png` : undefined;
}

export function launcherIcon(name: string): LauncherIcon | undefined {
  return LAUNCHER_ICONS.find(([n]) => n === name)?.[2];
}
