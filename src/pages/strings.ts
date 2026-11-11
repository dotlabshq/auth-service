import { translator, type Dictionary, type Lang } from '@baseworks/core/pages'

/**
 * Every sentence this service's pages show, in each language the frame knows.
 * A `{name}` is filled in escaped; the strings themselves are trusted markup.
 */
const STRINGS = {
  en: {
    signIn: 'Sign in',
    signInTo: 'Sign in to {name}',
    continue: 'Continue',
    continueWith: 'Continue with {provider}',
    or: 'or',
    otherOptions: 'Other sign-in options',
    devTag: 'DEV MODE',
    devHint: "This realm has no identity provider. The password is in auth-service's log.",
    devMismatch: 'That user and password do not match.',
    user: 'User',
    password: 'Password',
    errDenied: 'The sign-in was cancelled or refused. You can try again.',
    errSlow: 'That sign-in took too long, or was started in another browser. Please try again.',
    errProvider: 'The identity provider did not complete the sign-in. Please try again.',
    errUnknown: 'Something went wrong while signing you in. Please try again.',
    cliTitle: 'Authorize the CLI',
    cliAsk: 'A terminal is asking to sign in as <strong>{who}</strong>. Approve only if you started this yourself, just now.',
    approve: 'Approve',
    cliNotYou: 'Not you? Close this tab and nothing happens.',
    cliDoneTitle: 'Authorized',
    cliDone: 'Your terminal is signed in. You can close this tab.',
    cliMissing: 'This link is incomplete. Run the login command again and open the link it prints.',
    cliExpired: 'This sign-in request has expired or was never made. Run the login command again.',
    cliUsed: 'This sign-in request was already approved. If your terminal is not signed in, run the login command again.',
  },
  tr: {
    signIn: 'Giriş yap',
    signInTo: '{name} hesabınıza giriş yapın',
    continue: 'Devam et',
    continueWith: '{provider} ile devam et',
    or: 'veya',
    otherOptions: 'Diğer giriş seçenekleri',
    devTag: 'GELİŞTİRME MODU',
    devHint: 'Bu ortamda kimlik sağlayıcı yok. Parola auth-service günlüğünde yazıyor.',
    devMismatch: 'Kullanıcı adı ve parola eşleşmiyor.',
    user: 'Kullanıcı',
    password: 'Parola',
    errDenied: 'Giriş iptal edildi ya da reddedildi. Yeniden deneyebilirsiniz.',
    errSlow: 'Giriş çok uzun sürdü ya da başka bir tarayıcıda başlatıldı. Lütfen yeniden deneyin.',
    errProvider: 'Kimlik sağlayıcı girişi tamamlamadı. Lütfen yeniden deneyin.',
    errUnknown: 'Giriş yapılırken bir sorun oluştu. Lütfen yeniden deneyin.',
    cliTitle: 'Komut satırına izin ver',
    cliAsk: 'Bir terminal <strong>{who}</strong> olarak giriş yapmak istiyor. Yalnızca bunu az önce siz başlattıysanız onaylayın.',
    approve: 'Onayla',
    cliNotYou: 'Siz değil misiniz? Bu sekmeyi kapatın, hiçbir şey olmaz.',
    cliDoneTitle: 'İzin verildi',
    cliDone: 'Terminaliniz giriş yaptı. Bu sekmeyi kapatabilirsiniz.',
    cliMissing: 'Bu bağlantı eksik. Giriş komutunu yeniden çalıştırın ve yazdırdığı bağlantıyı açın.',
    cliExpired: 'Bu giriş isteğinin süresi dolmuş ya da hiç yapılmamış. Giriş komutunu yeniden çalıştırın.',
    cliUsed: 'Bu giriş isteği zaten onaylanmış. Terminaliniz giriş yapmadıysa giriş komutunu yeniden çalıştırın.',
  },
} satisfies Dictionary<string>

export type StringKey = keyof typeof STRINGS.en

export function strings(lang: Lang) {
  return translator(STRINGS as Dictionary<StringKey>, lang)
}
