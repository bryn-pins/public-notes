# public notes


## presenting markdown in terminal

- install rust
- `git checkout https://github.com/mfontanini/presenterm.git`
- build with sixel support: `cargo build --release --features sixel`
- run: `./target/release/presenterm {path-to-markdown.md}`
- with alias: `present src/oauth.md`
- config location: `~/.config/presenterm/config.yaml`
