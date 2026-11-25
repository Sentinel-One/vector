vim.lsp.config("rust_analyzer", {
  settings = { ["rust-analyzer"] = { cargo = { features = { "observo", "default" } } } },
})
