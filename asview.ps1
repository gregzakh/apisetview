using namespace System.IO
using namespace System.Drawing
using namespace System.Reflection
using namespace System.Windows.Forms
using namespace System.Linq.Expressions
using namespace System.Collections.Specialized
using namespace System.Runtime.InteropServices

Add-Type -AssemblyName System.Windows.Forms

$GetPeExports = {
  param([String]$Path)
  begin {
    $ConvertRvaToRaw = {
      param([UInt32]$Rva)
      end {
        $sections.ForEach{
          if (($Rva -ge $_.VirtualAddress) -and ($Rva -lt ($_.VirtualAddress + (
            ($_.VirtualSize -band ($sav - 1)) ? (($_.VirtualSize -band ($sav * -1)) + $sav) : $_.VirtualSize
          )))) { return ($Rva - ($_.VirtualAddress - $_.PointerToRawData)) }
        }
      }
    }

    $GetRawString = {
      param([UInt32]$Offset, [Switch]$NoMove)
      end {
        $cur = $fs.Position
        $fs.Position = $Offset
        while (($c = $br.ReadByte())) { $str += [Char]$c }
        if ($NoMove) { $fs.Position = $cur }
        return $str
      }
    }
  }
  end {
    try {
      $br = [BinaryReader]::new(($fs = [File]::OpenRead(($Path = Convert-Path -Path $Path))))
      $fs.Position = 0x3C
      $fs.Position = ($pes = $br.ReadInt32()) + 0x06
      $noh = $br.ReadUInt16() # IMAGE_FILE_HEADER->NumberOfSections
      $fs.Position += 0x0C
      $soh = $br.ReadUInt16() # IMAGE_FILE_HEADER->SizeOfOptionalHeader
      $ohs = $fs.Position + 0x02 # start of IMAGE_OPTIONAL_HEADER
      $fs.Position += 0x22
      $sav = $br.ReadUInt32() # IMAGE_OPTIONAL_HEADER->SectionAlignment
      $fs.Position = $ohs + $soh - 0x80 # Export Directory
      $va, $sz = $br.ReadUInt32(), $br.ReadUInt32()
      $fs.Position = $ohs + $soh # sections
      $sections = (1..$noh).ForEach{
        [PSCustomObject]@{
          Name = [String]::new($br.ReadBytes(0x08)).Trim("`0")
          VirtualSize = $br.ReadUInt32()
          VirtualAddress = $br.ReadUInt32()
          SizeOfRawData = $br.ReadUInt32()
          PointerToRawData = $br.ReadUInt32()
          PointerToRelocations = $br.ReadUInt32()
          PointerToLinenumbers = $br.ReadUInt32()
          NumberOfRelocations = $br.ReadUInt16()
          NumberOfLinenumbers = $br.ReadUInt16()
          Characteristics = $br.ReadUInt32()
        }
      }
      $fs.Position = & $ConvertRvaToRaw $va
      $IMAGE_EXPORT_DIRECTORY = [PSCustomObject]@{
        Characteristics = $br.ReadUInt32()
        TimeDateStamp = $br.ReadUInt32()
        MajorVersion = $br.ReadUInt16()
        MinorVersion = $br.ReadUInt16()
        Name = $br.ReadUInt32()
        Base = $br.ReadUInt32()
        NumberOfFunctions = $br.ReadUInt32()
        NumberOfNames = $br.ReadUInt32()
        AddressOfFunctions = $br.ReadUInt32()
        AddressOfNames = $br.ReadUInt32()
        AddressOfNameOrdinals = $br.ReadUInt32()
      }
      if (!$IMAGE_EXPORT_DIRECTORY.NumberOfFunctions -and !$IMAGE_EXPORT_DIRECTORY.NumberOfNames) {
        throw [InvalidOperationException]::new('Abnormal export directory data.')
      }

      $fs.Position = & $ConvertRvaToRaw $IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
      $funcs = @{}
      (1..$IMAGE_EXPORT_DIRECTORY.NumberOfFunctions).ForEach{
        $fwd = & $ConvertRvaToRaw ($adr = $br.ReadUInt32())
        $funcs[$IMAGE_EXPORT_DIRECTORY.Base + $_ - 1] = (
          ($va -lt $adr) -and ($adr -lt ($va + $sz))
        ) ? @{Address = ''; Forward = & $GetRawString $fwd -NoMove} : @{
          Address = $adr.ToString('X8'); Forward = ''
        }
      }
      $ords = & $ConvertRvaToRaw $IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
      $fs.Position = & $ConvertRvaToRaw $IMAGE_EXPORT_DIRECTORY.AddressOfNames
      (1..$IMAGE_EXPORT_DIRECTORY.NumberOfNames).ForEach{
        $cursor = $fs.Position
        $fs.Position = $ords
        $ord = $br.ReadUInt16() + $IMAGE_EXPORT_DIRECTORY.Base
        $ords = $fs.Position
        $fs.Position = $cursor

        ($item = $lvList2.Items.Add($ord)).SubItems.Add($funcs.$ord.Address)
        $item.SubItems.Add((& $GetRawString (& $ConvertRvaToRaw ($br.ReadInt32())) -NoMove))
        $item.SubItems.Add($funcs.$ord.Forward)
      }
    }
    catch { Write-Warning $_ }
    finally {
      ($br, $fs).ForEach{ if ($_) { $_.Dispose() } }
    }
  }
}

$GetMmPeExports = {
  param([String]$Module)
  end {
    $uint_sz, $ushort_sz = ([UInt32]0, [UInt16]0).ForEach{[Marshal]::SizeOf($_)}
    ($exp = $ExecutionContext.SessionState.PSVariable.Get("__$Module").Value) ? $exp : $(
      $mod = ($ps = Get-Process -Id $PID).Modules.Where{$_.ModuleName -match "^$Module"}.BaseAddress
      $ps.Dispose() && $($jmp = ($mov = [Marshal]::ReadInt32($mod, 0x3C)) + $uint_sz)
      $jmp = switch ([BitConverter]::ToUInt16([BitConverter]::GetBytes([Marshal]::ReadInt16($mod, $jmp)), 0)) {
        0x014C { 0x20, 0x78, 0x7C } 0x8664 { 0x40, 0x88, 0x8C } default{ [SystemException]::new() }
      }
      $tmp, $fun = $mod."ToInt$($jmp[0])"(), @{}
      $va, $sz = $jmp[1, 2].ForEach{[Marshal]::ReadInt32($mod, $mov + $_)}
      ($ed = @{bs = 0x10; nf = 0x14; nn = 0x18; af = 0x1C; an = 0x20; ao = 0x24}).Keys.ForEach{
        $val = [Marshal]::ReadInt32($mod, $va + $ed.$_)
        Set-Variable -Name $_ -Value ($_.StartsWith('a') ? $tmp + $val : $val) -Scope Script
      }
      function Assert-Forwarder([UInt32]$fa) { end { ($va -le $fa) -and ($fa -lt ($va + $sz)) } }
      (0..($nf - 1)).ForEach{
        $fun[$bs + $_] = (Assert-Forwarder ($fa = [Marshal]::ReadInt32([IntPtr]($af + $_ * $uint_sz)))) ? @{
          Address = ''; Forward = [Marshal]::PtrToStringAnsi([IntPtr]($tmp + $fa))
        } : @{ Address = [IntPtr]($tmp + $fa); Forward = '' }
      }
      Set-Variable -Name "__$Module" -Value ($exp = (0..($nn - 1)).ForEach{
        [PSCustomObject]@{
          Ordinal = ($ord = $bs + [Marshal]::ReadInt16([IntPtr]($ao + $_ * $ushort_sz)))
          Address = $fun[$ord].Address
          Name = [Marshal]::PtrToStringAnsi([IntPtr]($tmp + [Marshal]::ReadInt32([IntPtr]($an + $_ * $uint_sz))))
          Forward = $fun[$ord].Forward
        }
      }) -Option ReadOnly -Scope Global -Visibility Private
      $exp
    )
  }
}

$NativeCall = {
  param([String]$Module, [ScriptBlock]$Signature)
  end {
    $funcs, $exports = @{}, $GetMmPeExports.Invoke($Module)
    for ($i, $m, $fn, $p = 0, ([Expression].Assembly.GetType(
      'System.Linq.Expressions.Compiler.DelegateHelpers'
    ).GetMethod('MakeNewCustomDelegate', [BindingFlags]'NonPublic, Static')
    ), [Marshal].GetMethod('GetDelegateForFunctionPointer', ([IntPtr])),
    $Signature.Ast.FindAll({$args[0].CommandElements}, $true).ToArray();
    $i -lt $p.Length; $i++) {
      $fnret, $fname = ($def = $p[$i].CommandElements).Value
      $fnsig, $fnarg = $exports.Where{$_.Name -ceq $fname}.Address, $def.Pipeline.Extent.Text
      if (!$fnsig) { throw [InvalidOperationException]::new("Cannot find $fname signature.") }

      [Object[]]$fnarg = [String]::IsNullOrEmpty($fnarg) ? $fnret : (
        ($fnarg -replace '\[|\]' -split ',\s+').ForEach{
          $_.StartsWith('_') ? (Get-Variable $_.Remove(0, 1) -ValueOnly) : $_
        } + $fnret
      )
      $funcs[
        $fname.EndsWith('W') ? $fname.Substring(0, $fname.Length - 1) : $fname
      ] = $fn.MakeGenericMethod(
        [Delegate]::CreateDelegate([Func[[Type[]], Type]], $m).Invoke($fnarg)
      ).Invoke([Marshal], $fnsig)
    }

    Set-Variable -Name $Module -Value $funcs -Scope Global -Option ReadOnly -Force
  }
}

$GetApiSet = {
  end {
    $peb, $to_i = $ntdll.RtlGetCurrentPeb.Invoke(), "ToInt$(($sz = [IntPtr]::Size) * 0x08)"
    $ptr = [Marshal]::ReadIntPtr([IntPtr]($peb.$to_i() + ($sz -eq 8 ? 0x68 : 0x38))).$to_i()
    $count, $offset = (0x0C, 0x10).ForEach{ [Marshal]::ReadInt32([IntPtr]$ptr, $_) }
    $pasne = [IntPtr]($ptr + $offset) # *API_SET_NAMESPACE_ENTRY
    for ($i = 0; $i -lt $count; $i++) {
      $fl, $no, $nl, $vo, $vc = (0x00, 0x04, 0x08, 0x10, 0x14).ForEach{ [Marshal]::ReadInt32($pasne, $_) }
      $dll = "$([Marshal]::PtrToStringUni([IntPtr]($ptr + $no), $nl / 2)).dll"
      $pasve = [IntPtr]($ptr + $vo) # *API_SET_VALUE_ENTRY

      ($item = $lvList1.Items.Add($dll)).SubItems.Add([String][Boolean]$fl)
      $item.SubItems.Add($(for ($j = 0; $j -lt $vc; $j++) {
        $vvo, $vvl = (0x0C, 0x10).ForEach{ [Marshal]::ReadInt32($pasve, $_) }
        [Marshal]::PtrToStringUni([IntPtr]($ptr + $vvo), $vvl / 2)
        $pasve = [IntPtr]($pasve.$to_i() + 0x14)
      }) -join ', ')

      $item.ForeColor = [Color]( # existed sets highlights with blue color
        (Test-Path "$([Environment]::SystemDirectory)\downlevel\$dll") ? 'DarkBlue' : 'Crimson'
      )
      $pasne = [IntPtr]($pasne.$to_i() + 0x18)
    }
  }
}

<#$GetApiSetEx = {
  end {
    $rk = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\ApiSetSchemaExtensions'
    $rk.GetSubKeyNames().ForEach{ ($sub = $rk.OpenSubKey($_)).GetValue('FileName') && $sub.Dispose() }
    $rk.Dispose()
  }
}#>

$ConstructFormAndElements = {
  param([Array]$Names, [Type[]]$Elements, [Hashtable]$Property)
  end {
    if ($Names.Length -ne $Elements.Length) { throw [InvalidOperationException]::new('Element mismatch.') }
    for ($i = 0; $i -lt $Names.Length; $i++) {
      if (($x = $Names[$i]) -is [Array]) {
        (1..$x.Length).ForEach{
          Set-Variable -Name "$($x[0])$_" -Value (
            New-Object $Elements[$i] -Property $Property[$Elements[$i].Name]
          ) -Scope Script -Force
        }
      }
      else {
        Set-Variable -Name $x -Value (
          New-Object $Elements[$i] -Property $Property[$Elements[$i].Name]
        ) -Scope Script -Force
      }
    }
  }
}

& $ConstructFormAndElements -Names (
  'frmMain', 'scSplit', (,'lvList' * 2), (,'chCol_' * 7), 'sbStrip', 'sbLabel'
) -Elements (
  [Form], [SplitContainer], [ListView], [ColumnHeader], [StatusStrip], [ToolStripMenuItem]
) -Property @{
  Form = @{
    ClientSize = [Size]::new(800, 600)
    StartPosition = [FormStartPosition]::CenterScreen
    Text = 'ApiSet View'
  }
  SplitContainer = @{
    Dock = [DockStyle]::Fill
    Orientation = [Orientation]::Horizontal
    SplitterDistance = 58
    SplitterWidth = 1
  }
  ListView = @{
    Dock = [DockStyle]::Fill
    FullRowSelect = $true
    Multiselect = $false
    ShowItemToolTips = $false
    View = [View]::Details
  }
}
# scSplit
$scSplit.Panel1.Controls.Add($lvList1)
$scSplit.Panel2.Controls.Add($lvList2)
# lists
$lvList1.Columns.AddRange(($chCol_1, $chCol_2, $chCol_3))
$lvList2.Columns.AddRange(($chCol_4, $chCol_5, $chCol_6, $chCol_7))
$chCol_1.Text = $chCol_6.Text = 'Name'
$chCol_2.Text = 'Sealed'
$chCol_3.Text = 'Linked'
$chCol_4.Text = 'Ordinal'
$chCol_5.Text = 'Address'
$chCol_7.Text = 'Forward'
$lvList1.Add_SelectedIndexChanged({
  $lvList2.Items.Clear()
  $lvList1.SelectedItems.ForEach{
    $sbLabel.Text = $_.ForeColor -eq [Color]::DarkBlue ? "$(
      [Environment]::SystemDirectory
    )\downlevel\$($_.SubItems[0].Text)" : 'Not Found'
  }

  if ($sbLabel.Text -ne 'Not Found') {
    & $GetPeExports $sbLabel.Text
    $lvList2.AutoResizeColumns([ColumnHeaderAutoResizeStyle]::ColumnContent)
  }
})
# sbStrip
$sbStrip.Items.AddRange(($sbLabel))
$sbLabel.AutoSize = $true
# frmMain
$frmMain.Controls.AddRange(($scSplit, $sbStrip))
$frmMain.Add_Load({
  $NativeCall.Invoke('ntdll', {IntPtr RtlGetCurrentPeb})
  $GetApiSet.Invoke()
  $lvList1.AutoResizeColumns([ColumnHeaderAutoResizeStyle]::ColumnContent)
  $sbLabel.Text = 'Ready'
})
[void]$frmMain.ShowDialog()
