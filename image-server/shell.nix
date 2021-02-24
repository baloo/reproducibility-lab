{ pkgs ? import <nixpkgs> {}
}:

pkgs.mkShell rec {
    vimConfigured = pkgs.neovim.override {
      configure = {
        customRC = ''
          set mouse=
          autocmd BufWritePost,FileWritePost *.go execute 'GoMetaLinter'
        '';

        plug.plugins = with pkgs.vimPlugins; [
          vim-go
        ];
      };
    };
    shellHook = ''
      alias vi="${vimConfigured}/bin/nvim";
      alias vim=vi;

      if [ -z "$API_STARTER_GOPATH_SET" ]; then
        export GOPATH="$(pwd)/.go"
        export GOBIN="$GOPATH/bin"
        mkdir -p "$GOBIN"
        export PATH="$GOPATH/bin":$PATH
        export GO111MODULE=on
        export API_STARTER_GOPATH_SET=1
      fi
    '';

    buildInputs = with pkgs; [
        git
        man

        go_1_15
	golint

        openssl
    ];

}

