{
  description = "A very basic flake";

  outputs = { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in
    {
      packages.x86_64-linux.yurihaka = pkgs.python3Packages.buildPythonApplication {
        pname = "yurihaka";
        version = "0.1";
        src = ./.;
        propagatedBuildInputs = [
          pkgs.bcc
        ];
      };
      packages.x86_64-linux.default = self.packages.x86_64-linux.yurihaka;
      devShell.x86_64-linux = pkgs.mkShell {
        buildInputs = [
          pkgs.nixpkgs-fmt
          pkgs.bcc
        ];
      };
    };
}
