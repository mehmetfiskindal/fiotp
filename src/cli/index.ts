#!/usr/bin/env node
import { chmod, readFile, writeFile } from "node:fs/promises";
import * as readline from "node:readline";
import { FiotpService } from "../service/fiotp.js";
import { buildOtpAuthUri } from "../parser/otpauth.js";
import { renderQrTerminal } from "../qr/encode.js";

/** Yedek ve kasa dosyaları için izinler: yalnız sahip okuyup yazabilir. */
const FILE_MODE = 0o600;

const [command, vaultPath, argument] = process.argv.slice(2);

async function main(): Promise<void> {
  if (!command || !vaultPath) {
    printUsage();
    return;
  }

  if (command === "init") {
    const password = await getPassword("Master parola: ");
    await FiotpService.create(vaultPath, password);
    console.log(`Kasa oluşturuldu: ${vaultPath}`);
    return;
  }

  if (command === "recover") {
    await FiotpService.restoreBackup(vaultPath);
    console.log(`Kasa önceki iyi sürümden kurtarıldı: ${vaultPath}`);
    return;
  }

  const password = await getPassword("Master parola: ");
  const service = await FiotpService.open(vaultPath, password);

  switch (command) {
    case "add": {
      const value = argument ?? (await prompt("otpauth URI veya secret: "));
      if (value.startsWith("otpauth-migration://")) {
        const result = service.importMigration(value);
        await service.save();
        console.log(`${result.added} hesap içe aktarıldı.`);
        if (result.skippedMd5 > 0) {
          console.log(
            `Uyarı: ${result.skippedMd5} MD5 algoritmalı hesap desteklenmediği için atlandı.`,
          );
        }
        if (result.skippedInvalid > 0) {
          console.log(
            `Uyarı: ${result.skippedInvalid} geçersiz hesap atlandı.`,
          );
        }
      } else {
        const account = value.startsWith("otpauth://")
          ? service.addAccount(value)
          : service.addAccount({
              issuer: await prompt("Issuer: "),
              account: await prompt("Account: "),
              secret: value,
            });
        await service.save();
        console.log(`Hesap eklendi: ${account.id}`);
      }
      break;
    }
    case "list": {
      for (const account of service.listAccounts({ hideSecrets: true })) {
        const typeTag = account.type === "hotp" ? "[hotp] " : "";
        console.log(
          `${account.id}  ${typeTag}${account.issuer ? `${account.issuer}:` : ""}${account.account}`,
        );
      }
      break;
    }
    case "code": {
      const account = findAccount(service, argument);
      if (account.type === "hotp") {
        const result = service.getCode(account.id);
        console.log(`Kod: ${result.code} (HOTP, tek kullanımlık)`);
        service.lock();
        break;
      }
      printCode(service, account.id);
      const timer = setInterval(() => printCode(service, account.id), 1_000);
      process.once("SIGINT", () => {
        clearInterval(timer);
        service.lock();
        process.exit(0);
      });
      break;
    }
    case "qr": {
      const account = findAccount(service, argument);
      console.log(await renderQrTerminal(buildOtpAuthUri(account)));
      service.lock();
      break;
    }
    case "export": {
      if (!argument) throw new Error("export için çıktı dosyası zorunludur");
      await writeFile(argument, await service.exportBackup(), {
        encoding: "utf8",
        mode: FILE_MODE,
      });
      await chmod(argument, FILE_MODE);
      service.lock();
      console.log(`Şifreli yedek yazıldı: ${argument}`);
      break;
    }
    case "import": {
      if (!argument) throw new Error("import için yedek dosyası zorunludur");
      const backupPassword = await getPassword("Yedek master parolası: ");
      const backup = await readFile(argument, "utf8");
      const added = await service.importBackup(backup, backupPassword, "merge");
      service.lock();
      console.log(`${added} hesap içe aktarıldı.`);
      break;
    }
    case "passwd": {
      const newPassword = await getPassword(
        "Yeni master parola: ",
        "FIOTP_NEW_PASSWORD",
      );
      const confirmPassword = await getPassword(
        "Yeni master parola (tekrar): ",
        "FIOTP_NEW_PASSWORD",
      );
      if (newPassword !== confirmPassword) {
        service.lock();
        throw new Error("Yeni parolalar birbiriyle eşleşmiyor.");
      }
      await service.changeMasterPassword(password, newPassword);
      service.lock();
      console.log("Master parola değiştirildi.");
      break;
    }
    case "watch": {
      const accounts = service
        .listAccounts({ hideSecrets: true })
        .filter((account) => account.type !== "hotp");
      if (accounts.length === 0) {
        console.log("Canlı izlenecek TOTP hesabı yok.");
        service.lock();
        break;
      }
      const render = () => {
        process.stdout.write("\x1b[2J\x1b[H");
        console.log("fiotp — canlı kodlar (Ctrl+C ile çık)");
        console.log("─".repeat(40));
        for (const account of accounts) {
          const result = service.getCode(account.id);
          if (result.type !== "totp") continue;
          const label = account.issuer
            ? `${account.issuer}:${account.account}`
            : account.account;
          console.log(`${label.padEnd(28)} ${result.code}  ${result.remainingSeconds}s`);
        }
      };
      render();
      const timer = setInterval(render, 1_000);
      process.once("SIGINT", () => {
        clearInterval(timer);
        service.lock();
        process.exit(0);
      });
      break;
    }
    default:
      printUsage();
  }
}

function findAccount(service: FiotpService, selector: string | undefined) {
  const accounts = service.listAccounts();
  if (!selector) {
    if (accounts.length !== 1) throw new Error("Hesap ID'si zorunludur");
    return accounts[0]!;
  }
  const account = accounts.find(
    (candidate) => candidate.id === selector || candidate.account === selector,
  );
  if (!account) throw new Error(`Hesap bulunamadı: ${selector}`);
  return account;
}

function printCode(service: FiotpService, id: string): void {
  const result = service.getCode(id);
  if (result.type === "hotp") {
    process.stdout.write(`\rKod: ${result.code}   `);
    return;
  }
  process.stdout.write(`\rKod: ${result.code}  Kalan: ${result.remainingSeconds} sn   `);
}

function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/** Terminalde parolayı ekrana yazmadan okur. */
function getPassword(
  question: string,
  envName: string = "FIOTP_PASSWORD",
): Promise<string> {
  const fromEnv = process.env[envName];
  if (fromEnv) return Promise.resolve(fromEnv);
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    process.stdout.write(question);
    stdin.setRawMode?.(true);
    stdin.resume();
    let password = "";
    const onData = (chunk: Buffer) => {
      for (const byte of chunk) {
        if (byte === 3) {
          stdin.setRawMode?.(wasRaw ?? false);
          stdin.off("data", onData);
          process.stdout.write("\n");
          process.exit(130);
        } else if (byte === 13 || byte === 10) {
          stdin.setRawMode?.(wasRaw ?? false);
          stdin.off("data", onData);
          process.stdout.write("\n");
          resolve(password);
        } else if (byte === 127) {
          password = password.slice(0, -1);
        } else {
          password += String.fromCharCode(byte);
        }
      }
    };
    stdin.on("data", onData);
  });
}

function printUsage(): void {
  console.log(`Kullanım:
  fiotp init <kasa>
  fiotp add <kasa> [otpauth-uri|secret]
  fiotp list <kasa>
  fiotp code <kasa> [hesap-id|account]
  fiotp qr <kasa> <hesap-id|account>
  fiotp export <kasa> <yedek.json>
  fiotp import <kasa> <yedek.json>
  fiotp passwd <kasa>
  fiotp watch <kasa>
  fiotp recover <kasa>

Parola için FIOTP_PASSWORD ortam değişkeni de kullanılabilir.
passwd komutu yeni parolayı FIOTP_NEW_PASSWORD değişkeninden de okuyabilir.`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
