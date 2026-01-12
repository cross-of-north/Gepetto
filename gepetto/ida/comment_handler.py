import functools
import json
import re
import time
import textwrap
from urllib import response

import idaapi
import ida_hexrays
import ida_kernwin
import idc

import gepetto.config
from gepetto.models.model_manager import instantiate_model

_ = gepetto.config._

# -----------------------------------------------------------------------------

class CommentHandler(idaapi.action_handler_t):
    """
    This handler queries the model to generate a comment for the
    selected function. Once the reply is received, it is added
    as a function comment.
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        start_time = time.time()
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        
        pseudocode_lines = get_commentable_lines(decompiler_output)
        #print(pseudocode_lines)
        formatted_lines = format_commentable_lines(pseudocode_lines)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        #response =
        """{
  "227": "Initialize the COM library for use by the current thread.",
  "228": "Retrieve the current system time.",
  "229": "Calculate the milliseconds since the Unix epoch.",
  "230": "Store the calculated milliseconds since epoch.",
  "231": "Copy a pre-defined encrypted string into 'encryptedKey'.",
  "232": "Initialize 'tempStorage' to null.",
  "233": "Loop to iteratively process each character in the encrypted string.",
  "234": "Decrypt each character of the encrypted string by subtracting 9.",
  "238": "Initialize 'decryptedStrLength' to -1 to start counting string length.",
  "239": "Start counting the length of decrypted string.",
  "241": "Continue counting until a null character is reached.",
  "242": "Process the decrypted string.",
  "244": "Assign 'encryptedStr' pointer based on 'encodedBufferLength'.",
  "245": "If 'encodedBufferLength' is greater than 15, adjust 'encryptedStr'.",
  "252": "Retrieve the command line string in wide character format.",
  "253": "Parse the command line parameters into an array of strings.",
  "254": "Assign the address of parsed command line arguments to 'commandLineArgsBuffer'.",
  "257": "Initialize 'numCmdLineArgsMinusOne' to the count of command line arguments minus one.",
  "258": "Set 'processBuffer1' to null.",
  "259": "Initialize 'variable12' to zero.",
  "260": "Set 'processBuffer2' to null.",
  "261": "Initialize 'variable13' to zero.",
  "262": "Check if there is more than one command line argument.",
  "264": "Allocate space for processing command line arguments.",
  "265": "Initialize 'cmdArg' to point to the first argument.",
  "266": "Compute the remaining number of command line arguments.",
  "267": "Assign high order part of 'processBuffer2' to 'variable16'.",
  "268": "Set 'tempStorage' to 'processBuffer1'.",
  "271": "Compute the initial buffer offset based on command line arguments.",
  "274": "Calculate the temporary buffer position for processing arguments.",
  "275": "Retrieve value of the current command line argument.",
  "276": "Process each command line argument.",
  "279": "Continue processing until all command line arguments are finished.",
  "282": "Prepare variables for the next operations.",
  "286": "Clear 'processBuffer1' to null.",
  "287": "Clear 'processBuffer2' to null.",
  "288": "Save previous timestamp from encryptedKey.",
  "292": "Update 'encryptedKey' and buffers with processed data.",
  "297": "Finalize with the timeInfoBlock data.",
  "298": "Free previously allocated memory related to time values.",
  "299": "Perform cleanup for the 'processBuffer1'.",
  "301": "Release memory allocated for command line arguments.",
  "303": "Process another string with a custom function call.",
  "304": "Combine processed results into a string buffer.",
  "318": "Store a new encrypted string within the buffer.",
  "320": "Decrypt each character of a string by subtracting 2.",
  "321": "Handle a decrypted string with another custom function.",
  "325": "Conditional free of a data pointer if it is not part of special address space.",
  "327": "Perform a function call using parameters and store result.",
  "329": "Modify specific parts of 'processedArgNum' with specific values.",
  "331": "Iterate over specific characters to modify them by subtracting 9.",
  "333": "Prepare a result by calling another processing function.",
  "337": "Handle and free additional command line argument memory.",
  "343": "Prepare memory to be freed based on specific computed values.",
  "347": "Free old memory if it meets conditions from computation.",
  "349": "Initialize 'xorKey' with a constant value.",
  "360": "Copy a specific string into 'xorBuffer'.",
  "362": "Encrypt with an XOR operation with 'xorKey'.",
  "364": "Check result code of string processing and set boolean flag.",
  "372": "Set 'xorKey' to a different constant value.",
  "373": "Initialize 'xorBuffer' with another encrypted string.",
  "375": "Decrypt 'xorBuffer' by XORing with 'xorKey'.",
  "377": "Execute another string process with a custom sub-function.",
  "383": "Conditional decrement and free for a pointer.",
  "387": "Set up a freeing condition for allocated memory.",
  "391": "Free the memory if condition is met after checking.",
  "394": "Modify internal parts of 'processedArgNum' with specific values.",
  "396": "Modify specific values in 'processedArgNum' using XOR.",
  "399": "Process the modified command line arguments again.",
  "403": "Conditional free for specific buffer pointers.",
  "405": "Call another custom sub-function with internal calculation verification.",
  "407": "Determine match validity based on specific checks.",
  "409": "Store the match result into the 'validFlag'.",
  "411": "Modify the encrypted key once again and process.",
  "413": "Assign processed string back to relevant buffer pointer.",
  "417": "Free up memory for pointers no longer needed after processing.",
  "421": "Make another specific function call operating on a previous result.",
  "429": "Initialize part of 'encryptedKey' with a known string.",
  "431": "Process each byte of 'encryptedKey' using XOR computation.",
  "433": "Convert processed string and place it into a string buffer.",
  "434": "Prepare additional data manipulation function.",
  "443": "Relink list pointers after processing new entries.",
  "445": "Check and perform memory cleanup if a data block is no longer referenced.",
  "455": "Retrieve module handle if previous attempts failed.",
  "458": "Retrieve the path of the current executable.",
  "460": "Store multiple values into 'encryptedStringHolder'.",
  "464": "Modify and process each byte of 'encryptedStringHolder'.",
  "467": "Carry out detailed string process for command-line.",
  "473": "Manage pointer decrement and conditional freeing.",
  "478": "Conditionally increment the resource counter for specific resource.",
  "482": "Prepare a memory block for a custom free function call.",
  "484": "Execute a custom decrement and free task.",
  "490": "Execute a complex function call with multiple parameters.",
  "493": "Ensure that memory blocks are properly released.",
  "498": "Reassign the processed argument number to initial command line entries.",
  "502": "Handle the free operation on old command line list pointer.",
  "504": "Conduct a custom function cleanup operation.",
  "507": "Copy a specific string representation into 'encryptedKey'.",
  "509": "Update 'encryptedKey' with XOR computation and offset.",
  "511": "Execute a custom function call with derived arguments.",
  "513": "Carry out another data transformation.",
  "519": "Perform structured memory release after string processing.",
  "526": "Fill in 'encryptedKey' with another predefined string.",
  "528": "Iterate to decrement bytes in 'encryptedKey'.",
  "530": "Use a wine library call to convert epoch milliseconds to string.",
  "532": "Handle wide char string conversion into UTF-8 equivalents.",
  "535": "Carry out a secondary detailed processing function.",
  "537": "Free memory being no longer used after the operation.",
  "539": "Complete any remaining memory cleanups ensuring nothing is orphaned.",
  "548": "Check whether debugger is actively present.",
  "557": "Initialize 'processBuffer2' with a specific encrypted string.",
  "559": "Decrypt each character within processBuffer1 by XOR.",
  "561": "Transform string with another custom process through a function call.",
  "566": "Process result values through an extended custom function call.",
  "573": "Carry out further structured process function after cleanup.",
  "579": "Perform custom interlocked operation with derived parameters.",
  "583": "Execute a special unwind operation for error handling.",
  "585": "Finish planned runtime steps through a predefined sub-function.",
  "595": "Check for debugger presence before executing specific methods.",
  "598": "Reset dynamic buffer space and entries after operations.",
  "608": "XOR 'resultBuffer' with a simple loop to modify data.",
  "611": "Conduct cleanup of encryptedKey with result buffer.",
  "617": "Invoke a dynamic buffer transformation call using complex methods.",
  "626": "Take care of special interlocked increment operations.",
  "635": "Verify and implement buffer operations, releasing older entries.",
  "640": "Transfer buffer objects to a new location after adjustment.",
  "654": "Complete function call using buffer data.",
  "660": "Perform function cleanup with reset operations.",
  "664": "Conduct XOR calculation on processBuffer1 range.",
  "666": "Call transformation function with resultBuffer data.",
  "671": "Perform decrement operations to prepare data release.",
  "673": "Prepare position-related operations over list materials.",
  "679": "Perform specific operations on buffer lists and prepare release.",
  "689": "Evaluate buffer data length and take necessary actions.",
  "695": "Adjust dynamicBuffer1 using calculated parameters.",
  "706": "Leverage a function class move reset using provided reference.",
  "712": "Allocate new material position entries over encoded data.",
  "721": "Carry out operations to prepare buffer alignment.",
  "727": "Leverage routine to load positions with callback handler.",
  "731": "Regularize buffer with function call adjustments.",
  "733": "Utilize custom transformations to elevate to new buffer index.",
  "742": "Search for function capable of matching contextual info.",
  "744": "Assess dynamic buffer identifiers length or range.",
  "750": "Push and store list buffer into a new position.",
  "756": "Run transformation method over regular scheduled data.",
  "760": "Regenerate the function class using an accompanied reference.",
  "766": "Reset and clear indexes on dynamic buffer materials.",
  "771": "Set up raw data buffers with standard reference flags.",
  "775": "Update list using offset patterns from extracted letters.",
  "778": "Perform cleanup on buffer entries with range-fixed process.",
  "783": "Release memory sections detached from buffer structures.",
  "786": "Execute key processing operation incorporating multiple function classes.",
  "795": "Carry out sub-function operations verging on local buffer increment.",
  "799": "Adjust function utilizing comparable structure class info.",
  "804": "Direct data into dynamic buffer position before reset.",
  "809": "Move list material entries into a predefined buffer context.",
  "824": "Reset initial entries and redirect bufferList within function.",
  "830": "Hold byte decrement through controlled character range.",
  "833": "Reassign double checked output on string operation method.",
  "838": "Provide decimal element buffer resolution through calculations.",
  "848": "Push the list indices internal to buffer methods.",
  "853": "Isolate system elements for targeted identification relocation.",
  "861": "Distribute memory blocks systematically adjusting the buffer.",
  "877": "Identify start and end positions within multiple buffer lists.",
  "888": "Loop through control flow to validate buffer operability.",
  "894": "Evaluate buffer conditions promting segmentation strategy.",
  "911": "Dispatch sub-method execution on accurately obtained context.",
  "918": "Perform error uncaught condition by way of strategies.",
  "931": "Adjust memory handling strategies and position beforehand.",
  "954": "Verify pointer position within method buffers.",
  "957": "Allow optional method space on designated required fields.",
  "964": "Utilize a function method that proceeds to next entry.",
  "976": "Confirm values over delegated set actions on entry.",
  "982": "Opt-in for free method activity for managed buffers.",
  "990": "Leave unextended path to prolonged sub-function instances.",
  "1005": "Check within determined pointer specifications increment buffer.",
  "1009": "Properly handle partial conditions based on references.",
  "1017": "Declare result responses with default related checks to memory.",
  "1022": "Execute constructed values with designated structure metrics.",
  "1026": "Manage transitions through byte sequences handled normally.",
  "1031": "Account for spatial conditions without signal interference.",
  "1035": "Coordinate stored patterns and data for consistent interpretations.",
  "1043": "Deliver assessment using practiced values for managing control.",
  "1044": "Process and result associations merged in calculated manner.",
  "1057": "The usage of guarding value is shared across a wider range.",
  "1061": "Perform cleanup of memorized segment allocations handled responsibly.",
  "1063": "Reorient deprecated configuration layers upon call functional completion.",
  "1069": "Conclude detachment via in-depth tracking area operation.",
  "1075": "Confirm any necessary pointer release after processing efforts.",
  "1081": "Emphasize sub-navigation coordination on buffer plane.",
  "1087": "Structure final context settings for proper routines alignment.",
  "1094": "Transact buffer paths for managed distributions due to buffer deviations.",
  "1097": "Release memory contingent positions over pre-allocated areas.",
  "1102": "Uninitialize the COM library for use by the current thread.",
  "1103": "Return a value indicative of function's expected completion."
}"""
        #comment_callback(decompiler_output, pseudocode_lines, v, response, start_time)
        gepetto.config.model.query_model_async(
            _(f"""
                RESPONSE STRICTLY IN THE FORMAT JSON MAP {{ lineNumber: "comment" }}, NOTHING ELSE!!!
                Add comments that explain what is happening in this C function.
                You can ONLY add comments to lines that start with a '+'!
                DON'T comment trivial or obvious actions; comment on important or non-obvious blocks; read ENTIRE logical blocks before make a comment.
                \n
                ```C
                {formatted_lines}
                ```
              """),
            functools.partial(comment_callback, decompiler_output=decompiler_output, pseudocode_lines=pseudocode_lines, view=v, start_time=start_time),
            additional_model_options={"response_format": {"type": "json_object"}})
        print(_("Request to {model} sent...").format(model=str(gepetto.config.model)))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------

def comment_callback(decompiler_output, pseudocode_lines, view, response, start_time):
    """
    Callback that sets a comment at the given address.
    :param decompiler_output: The decompiler output object
    :param pseudocode_lines: List of tuples containing pseudocode line information
    :param view: A handle to the decompiler window
    :param response: The comment to add
    :param start_time: The time when the request was sent, used for calculating elapsed time
    """
    try:
        elapsed_time = time.time() - start_time

        print(f"Response: {response}")

        items = json.loads(response)
        pairs = [(int(line), comment) for line, comment in items.items()]
        print(f"Pairs: {pairs}")

        prev_comment_address = None
        prev_comment_placement = None
        if len(pseudocode_lines) > 0:
            prev_comment_address = pseudocode_lines[0][2]  # Get the first comment address
            prev_comment_placement = pseudocode_lines[0][3]  # Get the first comment placement
        for line, comment in pairs:

            #print(f"Setting comment for line {line}")

            comment_address = None
            comment_placement = 0
            if 0 <= line < len(pseudocode_lines):
                comment_address = pseudocode_lines[line][2]  # Get the comment address
                comment_placement = pseudocode_lines[line][3]  # Get the comment placement

            #print(f"at address {comment_address} with placement {comment_placement}")

            if comment_address is None:
                if prev_comment_address is None:
                    print(f"Skipping line {line} as it has no comment address.")
                    continue
                comment_address = prev_comment_address

            if comment_placement == 0:
                if prev_comment_placement is None:
                    print(f"Skipping line {line} as it has no valid comment placement.")
                    continue
                comment_placement = prev_comment_placement
            prev_comment_address = comment_address
            prev_comment_placement = comment_placement

            target = idaapi.treeloc_t()
            target.ea = comment_address
            target.itp = comment_placement
            decompiler_output.set_user_cmt(target, comment)

        decompiler_output.save_user_cmts()
        decompiler_output.del_orphan_cmts()

        if view:
            view.refresh_view(True)

        print(_("{model} query finished in {time:.2f} seconds!").format(
            model=str(gepetto.config.model), time=elapsed_time))
        
    except Exception as e:
        print("[ERROR] comment_callback:", e)
        raise


# -----------------------------------------------------------------------------

def get_commentable_lines(cfunc):
    """
    Extracts information for each line of decompiled pseudocode, including:
      - lineIndex: Line number in the pseudocode listing (starting from 0).
      - lineText: Cleaned text of the line (IDA formatting tags removed).
      - comment_address: Address in the decompiled function suitable for attaching a comment, or BADADDR if unavailable.
      - comment_placement: Comment placement type (e.g., ITP_SEMI, ITP_COLON), or 0 if unavailable.
      - has_user_comment: True if a user comment already exists for this line, otherwise False.

    Args:
        cfunc (idaapi.cfuncptr_t): Decompiled function object.

    Returns:
        List of tuples: (lineIndex, lineText, comment_address, comment_placement, has_user_comment)
    """
    result = []

    pseudocode_lines = cfunc.get_pseudocode()
    
    place_comments_above = (gepetto.config.get_config("Gepetto", "COMMENT_POSITION", default="above") == "above")

    for idx, line in enumerate(pseudocode_lines):
        # Clean line text from formatting tags
        try:
            line_text = idaapi.tag_remove(line.line)
        except Exception:
            line_text = str(line.line)

        # Lookup ctree item
        phead = idaapi.ctree_item_t()
        pitem = idaapi.ctree_item_t()
        ptail = idaapi.ctree_item_t()

        phead_addr = None
        phead_place = None
        ptail_addr = None
        ptail_place = None
        
        has_user_comment = False
        comment_address = None
        comment_placement = 0

        found = cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail)
        if found:
            # Invert preferred locations order
            if not place_comments_above:
                tmp = phead
                phead = ptail
                ptail = tmp
                
            # Assign locations if available and valid
            if hasattr(phead, "loc") and phead.loc and phead.loc.ea != idaapi.BADADDR:
                has_user_comment |= (cfunc.get_user_cmt(phead.loc, True) is not None)
                phead_addr = phead.loc.ea
                phead_place = phead.loc.itp
            if hasattr(ptail, "loc") and ptail.loc and ptail.loc.ea != idaapi.BADADDR:
                has_user_comment |= (cfunc.get_user_cmt(ptail.loc, True) is not None)
                ptail_addr = ptail.loc.ea
                ptail_place = ptail.loc.itp

            # Pick final address and placement (prefer phead if present)
            if phead_addr is not None:
                comment_address = phead_addr
                comment_placement = phead_place
            elif ptail_addr is not None:
                comment_address = ptail_addr
                comment_placement = ptail_place

        result.append((idx, idaapi.tag_remove(line_text), comment_address, comment_placement, has_user_comment))

    return result

# -----------------------------------------------------------------------------

def format_commentable_lines(commentable_lines):
    """
    Formats the output of get_commentable_lines() for display.

    For each line:
      - Adds a "+" before the index if a comment address exists and the line does not already have a user comment.
      - Formats as: [+]index<TAB>text

    Args:
        commentable_lines: List of tuples (index, text, comment_address, comment_placement, has_user_comment)

    Returns:
        str: The formatted text as a single string, with one line per entry.
    """
    output = []
    for idx, text, comment_address, comment_placement, has_user_comment in commentable_lines:
        
        # Add "+" if the line can be commented and has no user comment yet
        prefix = "+" if comment_address is not None and not has_user_comment else ""
        
        output.append(f"{prefix}{idx}\t{text}")
    return "\n".join(output)

# -----------------------------------------------------------------------------

