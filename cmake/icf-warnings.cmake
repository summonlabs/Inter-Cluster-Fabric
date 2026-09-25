# Project warning policy. The runtime must build warning-clean in Release and Debug.
function(icf_set_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /Zc:preprocessor /utf-8 /EHsc)
    # C4820: padding added after a data member. Protocol record layouts are explicit and
    #        padding is intentional; the warning is noise for wire/model structs.
    # C4514: unreferenced inline function removed. Headers are shared across translation
    #        units, so unused inline helpers are expected.
    target_compile_options(${target} PRIVATE /wd4820 /wd4514)
    if(ICF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
      -Wold-style-cast -Wnon-virtual-dtor -Woverloaded-virtual)
    if(ICF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()
