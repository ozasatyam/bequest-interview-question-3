import Dexie from 'dexie';

interface Backup {
  id?: number;
  versionHistory: any[];
  lastBackup: number;
}

class BackupDatabase extends Dexie {
  backups!: Dexie.Table<Backup, number>;

  constructor() {
    super('BackupDatabase');
    this.version(1).stores({
      backups: '++id,lastBackup'
    });
  }
}

export const db = new BackupDatabase();