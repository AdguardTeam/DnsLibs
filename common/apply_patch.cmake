function(apply_patch patch working_directory)
    execute_process(
            COMMAND git apply --reverse --check -p0
            WORKING_DIRECTORY "${working_directory}"
            INPUT_FILE "${patch}"
            RESULT_VARIABLE RESULT
    )

    if (RESULT EQUAL 0)
        message(STATUS "Patch is already applied ${patch}")
    else ()
        message(STATUS "Applying ${patch}")
        execute_process(
                COMMAND git apply --verbose --ignore-whitespace -p0
                WORKING_DIRECTORY "${working_directory}"
                INPUT_FILE "${patch}"
                RESULT_VARIABLE RESULT
        )

        if (RESULT EQUAL 0)
            message(STATUS "Patch applied: ${patch}")
        else ()
            message(FATAL_ERROR "Error applying patch ${patch}")
        endif ()
    endif ()
endfunction()
