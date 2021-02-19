# t2plugin

This crate allows to easily develop [Rust](https://www.rust-lang.org/) plugins for
[Tranalyzer2](https://tranalyzer.com/), a network traffic analysis tool.

## Documentation

<https://tranalyzer.com/rustdoc/t2plugin/>

## Example plugin

<https://github.com/Tranalyzer/rustExample>

## Create a new plugin

1. [Download](https://tranalyzer.com/downloads) and
   [install](https://tranalyzer.com/tutorial/installation) Tranalyzer2.

2. Create a new Rust plugin

        cd $T2HOME/plugins
        t2plugin --rust -c myPluginName
        cd myPluginName

3. Optional: change the `PLUGINORDER` at the top of `autogen.sh`.

4. Fill the different methods of the
   [`T2Plugin`](https://tranalyzer.com/rustdoc/t2plugin/trait.T2Plugin.html) trait
   implementation in `src/lib.rs`.
