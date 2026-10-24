# kam1tsur3-web

Hexo + NexTで生成し、GitHub Pagesで公開するブログ。
公開URL: https://kam1tsur3.org/

## ローカルでの実行

Node.js 24とnpmを使用する。

```sh
git clone --recurse-submodules git@github.com:kam1tsur3/kam1tsur3-web.git
cd kam1tsur3-web
npm ci
npm run server
```

既存のチェックアウトでは `git submodule update --init --recursive` でテーマを取得する。
テーマのカスタマイズは `_config.yml` の `theme_config` に記述する。

```sh
npm run clean
npm run build
```

生成物は `public/` に出力される。`main` へのpush、またはActionsの
「Deploy blog to GitHub Pages」の「Run workflow」でビルド・公開する。

## GitHub Pagesへの初回移行

1. この変更をGitHubの `main` にpushする。
2. リポジトリの Settings → Pages → Build and deployment → Sourceを
   **GitHub Actions** に設定する。
3. 同じ画面のCustom domainに `kam1tsur3.org` を設定して保存する。
   Actionsによる公開では `CNAME` ファイルだけでは設定できないため、必ず画面で設定する。
4. Actionsのデプロイが成功することを確認する。設定前のpushで失敗していた場合は再実行する。
5. DNS管理画面で、`kam1tsur3.org` の既存のVPS向けAレコードを以下の4件に置き換える。

   | 種別 | 名前 | 値 |
   | --- | --- | --- |
   | A | @ | 185.199.108.153 |
   | A | @ | 185.199.109.153 |
   | A | @ | 185.199.110.153 |
   | A | @ | 185.199.111.153 |

   VPS向けのAAAAレコードがあれば削除するか、GitHub PagesのIPv6アドレスに置き換える。
   メール用のMXやTXTなど、ブログ以外のレコードは維持する。
6. DNSチェック・証明書発行後、Pagesの **Enforce HTTPS** を有効にする。
7. `https://kam1tsur3.org/` の記事一覧、既存の記事URL、画像、タグ、Aboutを確認する。
   DNS反映には最大24時間かかる場合がある。切り替えを確認し、VPSの他用途や
   必要なデータのバックアップも確認してからVPSを解約する。

`_config.yml` の `url` と `permalink` は既存の設定を維持しているため、
同じドメインで既存の記事URLを引き継ぐ。
この構成は独自ドメインでの公開を前提とする。

- [Hexo: GitHub Pages](https://hexo.io/docs/github-pages.html)
- [GitHub: 独自ドメインの管理・DNSの設定値](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site)
