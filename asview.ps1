using namespace System.IO

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

        [PSCustomObject]@{
          Ordinal = $ord
          Address = $funcs.$ord.Address
          Name = & $GetRawString (& $ConvertRvaToRaw ($br.ReadUInt32())) -NoMove
          ForwardedTo = $funcs.$ord.Forward
        }
      }
    }
    catch { Write-Warning $_ }
    finally {
      ($br, $fs).ForEach{ if ($_) { $_.Dispose() } }
    }
  }
}

#& $GetPeExports "$([Environment]::SystemDirectory)\downlevel\api-ms-win-core-processthreads-l1-1-2.dll"
