#include <pspkernel.h>
#include <pspdebug.h>
#include <pspdisplay.h>
#include <psputils.h>
#include <pspctrl.h>
#include <pspgu.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "hmac-sha1/src/hmac/hmac.h"
#include "base32/base32.h"
#include "totp.h"
#include "common/callback.h"

#include "intrafont031g/libraries/graphics.h"
#include "intrafont031g/intraFont.h"

#define VERS 1 // version
#define REVS 0 // revision

PSP_MODULE_INFO("TOTP", PSP_MODULE_USER, VERS, REVS);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER);
PSP_HEAP_THRESHOLD_SIZE_KB(0);

#define printf pspDebugScreenPrintf

enum ALGTYPE
{
    SHA1,
    SHA256,
    SHA512
};


char otpfile[] = "ms0:/PSP/COMMON/OTPAUTH_KEYS";

  // Colors
  enum colors {
    RED =  0xFF0000FF,
    GREEN =  0xFF00FF00,
    BLUE =  0xFFFF0000,
    WHITE =  0xFFFFFFFF,
    LITEGRAY = 0xFFBFBFBF,
    GRAY =  0xFF7F7F7F,
    DARKGRAY = 0xFF3F3F3F,    
    BLACK = 0xFF000000,
  };

int
main(int argc, char **argv)
{
    pspDebugScreenInit(); 
    setupExitCallback();
    intraFontInit();

    SceCtrlData buttonInput;
    sceCtrlSetSamplingCycle(0);
	sceCtrlSetSamplingMode(PSP_CTRL_MODE_ANALOG);
    
    // Load fonts
    intraFont* ltn[16];                                         //latin fonts (large/small,with/without serif,regular/italic/bold/italic&bold)
    char file[40];
    int i;
    for (i = 0; i < 16; i++) {
        sprintf(file,"flash0:/font/ltn%d.pgf",i); 
        ltn[i] = intraFontLoad(file,INTRAFONT_CACHE_ALL);
        pspDebugScreenSetXY(15,2);
        pspDebugScreenPrintf("%d%%",(i+1)*100/20);
    }

    if(!ltn[0] || !ltn[4] || !ltn[8]) sceKernelExitGame();

    uint32_t counter = 0;

    printf("Reading OTPauth keys...");
    struct OTPKey *head = readOTPFile(otpfile);

    struct OTPKey *cur;

    float x_label = 130;
    float x_code = 5;
    int vscroll_offset = 0;
    initGraphics();


    while (isRunning())
    {
        pspDebugScreenSetXY(0, 0);

        clearScreen(BLACK);
        intraFontSetStyle(ltn[8],2.0f,WHITE,0U,0.f,0);
        intraFontSetStyle(ltn[6],1.0f,WHITE,0U,0.f,INTRAFONT_SCROLL_LEFT);
        float y = 20;

        // Must be called before any of the intraFont functions
        guStart();

        time_t now;
        sceKernelLibcTime(&now);
        counter = now / 30;
        // printf(" Next Refresh: %lld s \n", 30 - (now % 30));
        // printf(" Counter: %ld, ts: %lld \n", counter, now);
        // printf("\n");
        // Continue and don't clear the screen when the counter has not been changed
        // TODO: Make counter check per token with different periods
        // if (counter == prev_counter)
        //     continue;

        // prev_counter = counter;

        cur = head;
        int curpos = 0;
        int shown = 0;

        sceCtrlPeekBufferPositive(&buttonInput, 1);
        if(buttonInput.Buttons != 0) 
		{ 
            if(buttonInput.Buttons & PSP_CTRL_UP) {
                if (vscroll_offset > 0) vscroll_offset -= 1;
            }
			if(buttonInput.Buttons & PSP_CTRL_DOWN) {
                if (vscroll_offset < (num_otp_keys - 12)) vscroll_offset += 1;
            }
        }

        while(curpos < vscroll_offset) { 
            cur = cur->next;
            curpos += 1;
        }
        
        while (cur != NULL && shown < 12)
        {   
            int code = calcToken(cur, counter);
            char strcode[7];
            sprintf(strcode, "%06ld", mod_hotp(code, cur->digits));
            intraFontPrint(ltn[6],x_label,y-4,cur->name);
            intraFontPrint(ltn[8],x_code,y,strcode);
            y += 22;

            // printf(" > %s %06d \n", cur->name, mod_hotp(code, cur->digits));
            shown += 1;
            cur = cur->next;
        }

        // End drawing
        sceGuFinish();
        sceGuSync(0,0);
        
        // // Swap buffers
        sceDisplayWaitVblankStart();
        flipScreen();
    }

    sceKernelExitGame();

    return 0;
}