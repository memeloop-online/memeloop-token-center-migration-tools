export function archiveErrorDiagnostic(error: unknown): string {
  const value = error !== null && typeof error === "object" ? error as Record<string, unknown> : {};
  const knownCodes = new Set(["EACCES", "EPERM", "EROFS", "ENOENT", "ENOSPC", "EDQUOT", "EIO", "EMFILE", "ENFILE", "EEXIST", "EISDIR", "ENOTDIR", "ELOOP", "ERR_SQLITE_ERROR", "ERR_SQLITE_NOT_OPEN", "ERR_SQLITE_BUSY", "ERR_OUT_OF_RANGE", "ERR_INVALID_ARG_TYPE"]);
  const code = typeof value.code === "string" && knownCodes.has(value.code) ? value.code : "UNCLASSIFIED";
  const sqliteCode = code === "ERR_SQLITE_ERROR" && Number.isSafeInteger(value.errcode) && Number(value.errcode) >= 0 && Number(value.errcode) <= 65535
    ? ` sqlite_errcode=${Number(value.errcode)}` : "";
  return `delta export failed: code=${code}${sqliteCode}`;
}
