rule Webshell_Eval_Marker
{
    meta:
        author = "blueteam-os"
        description = "Common PHP webshell eval/assert markers. Subset matcher only."
        version = "1.0.0"
    strings:
        $a = "eval($_POST"
        $b = "assert($_POST"
        $c = "eval($_GET"
    condition:
        any of them
}
