/**
 * installerror.ts: the one error type `switchboard install` / `uninstall` raise when it will not (or cannot) go on.
 *
 * A refusal is a normal outcome, not a crash: an unparseable client file, an unsupported scope, a mode the client
 * cannot express without writing a token into its config. The message is printed as one clear line and the process
 * exits 1; nothing has been changed when one is thrown during planning.
 */
export class InstallRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InstallRefusal";
  }
}
