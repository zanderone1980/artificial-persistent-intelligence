/**
 * VIGIL Log Rotation — Automatic Alert Log Management
 *
 * Prevents unbounded log growth with:
 *   - Size-based rotation
 *   - Compression (gzip)
 *   - Retention policies
 *   - Archival to timestamped files
 *
 * Zero external dependencies (uses Node.js zlib).
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { EventEmitter } = require('events');

const DEFAULTS = {
  maxSizeBytes: 10 * 1024 * 1024,  // 10MB before rotation
  maxFiles: 10,                     // Keep 10 rotated files
  compress: true,                   // Gzip old files
  archiveDir: null,                 // Separate archive dir (default: same dir)
};

class LogRotator extends EventEmitter {
  constructor(logPath, options = {}) {
    super();
    this.logPath = logPath;
    this.config = { ...DEFAULTS, ...options };
    this.archiveDir = this.config.archiveDir || path.dirname(logPath);
    this.baseName = path.basename(this.logPath);
    this.dirName = path.dirname(this.logPath);

    // Ensure archive dir exists
    if (!fs.existsSync(this.archiveDir)) {
      fs.mkdirSync(this.archiveDir, { recursive: true });
    }

    this.stats = {
      rotations: 0,
      bytesWritten: 0,
      bytesArchived: 0,
      filesDeleted: 0,
    };
  }

  /**
   * Check if rotation is needed and perform it.
   * Call this before writing to the log.
   * @returns {boolean} true if rotation was performed
   */
  checkAndRotate() {
    if (!fs.existsSync(this.logPath)) {
      return false;
    }

    const stats = fs.statSync(this.logPath);
    if (stats.size < this.config.maxSizeBytes) {
      return false;
    }

    this.rotate();
    return true;
  }

  /**
   * Force a rotation.
   */
  rotate() {
    if (!fs.existsSync(this.logPath)) {
      return;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const rotatedName = `${this.baseName}.${timestamp}`;
    const rotatedPath = path.join(this.archiveDir, rotatedName);

    // Move current log to rotated name
    fs.renameSync(this.logPath, rotatedPath);

    // Create empty new log
    fs.writeFileSync(this.logPath, '', 'utf8');

    this.stats.rotations++;
    this.emit('rotate', { oldPath: this.logPath, newPath: rotatedPath });

    // Compress if enabled
    if (this.config.compress) {
      this._compress(rotatedPath);
    }

    // Enforce retention
    this._enforceRetention();
  }

  /**
   * Compress a rotated log file.
   * @private
   */
  _compress(filePath) {
    const content = fs.readFileSync(filePath);
    const compressed = zlib.gzipSync(content);
    const compressedPath = filePath + '.gz';

    fs.writeFileSync(compressedPath, compressed);
    fs.unlinkSync(filePath); // Delete uncompressed

    this.stats.bytesArchived += compressed.length;
    this.emit('compress', { path: compressedPath, originalSize: content.length, compressedSize: compressed.length });
  }

  /**
   * Delete old rotated files beyond maxFiles.
   * @private
   */
  _enforceRetention() {
    const files = fs.readdirSync(this.archiveDir)
      .filter(f => f.startsWith(this.baseName + '.'))
      .sort()
      .reverse(); // Newest first

    // Delete files beyond maxFiles
    const toDelete = files.slice(this.config.maxFiles);
    for (const file of toDelete) {
      const filePath = path.join(this.archiveDir, file);
      const stats = fs.statSync(filePath);
      fs.unlinkSync(filePath);
      this.stats.filesDeleted++;
      this.emit('delete', { path: filePath, size: stats.size });
    }
  }

  /**
   * Write to log with automatic rotation check.
   * @param {string} data - Data to write
   * @param {boolean} newline - Append newline (default: true)
   */
  write(data, newline = true) {
    this.checkAndRotate();

    const content = newline ? data + '\n' : data;
    fs.appendFileSync(this.logPath, content, 'utf8');
    this.stats.bytesWritten += Buffer.byteLength(content, 'utf8');
  }

  /**
   * Get current log size.
   * @returns {number} Size in bytes
   */
  getSize() {
    if (!fs.existsSync(this.logPath)) {
      return 0;
    }
    return fs.statSync(this.logPath).size;
  }

  /**
   * List all archived log files.
   * @returns {Array<{name, path, size, compressed}>}
   */
  listArchives() {
    if (!fs.existsSync(this.archiveDir)) {
      return [];
    }

    return fs.readdirSync(this.archiveDir)
      .filter(f => f.startsWith(this.baseName + '.'))
      .map(name => {
        const filePath = path.join(this.archiveDir, name);
        const stats = fs.statSync(filePath);
        return {
          name,
          path: filePath,
          size: stats.size,
          compressed: name.endsWith('.gz'),
          mtime: stats.mtime,
        };
      })
      .sort((a, b) => b.mtime - a.mtime);
  }

  /**
   * Get stats.
   */
  getStats() {
    return {
      ...this.stats,
      currentSize: this.getSize(),
      archiveCount: this.listArchives().length,
    };
  }

  /**
   * Clear all archives.
   */
  clearArchives() {
    const archives = this.listArchives();
    for (const archive of archives) {
      fs.unlinkSync(archive.path);
      this.stats.filesDeleted++;
    }
    this.emit('clear', { deleted: archives.length });
  }
}

module.exports = {
  LogRotator,
  DEFAULTS,
};
