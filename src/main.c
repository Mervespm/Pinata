//Main file for Riscure Pinata Board rev4.0 -- Falcon (FN-DSA) SCA build
//Riscure 2014-2019, 2026
//
//Code revision: 	4.0 -- 2026/03/24
//
//This is a Falcon-only trimmed variant of the Pinata main.c: all classic
//software/hardware crypto commands (AES, DES, TDES, SM4, PRESENT, TEA/XTEA,
//RSA, ECC, HW crypto engine, password-check glitching, ...) and the
//ML-DSA/ML-KEM commands have been removed, leaving only Falcon key loading,
//signing and verification plus the generic board infrastructure they need.

#include "main.h"
#include "io.h"
#include <setjmp.h>

#include "falcon/wrapper.h"
#include "pqm4_hal/pinata_callbacks.h"

// If a byte the host promised (e.g. the rest of a SET_KEY/SIGN payload)
// never arrives - dropped on the wire - get_char_uart() used to spin
// forever with no way to recover short of a physical reset. command_resync
// is the point the main loop jumps back to when that timeout fires, so a
// dropped byte becomes "that command failed" instead of a permanent hang.
jmp_buf command_resync;

// Belt-and-suspenders backstop for the same problem: the independent
// hardware watchdog (IWDG) runs off its own internal ~32kHz clock,
// completely separate from the main clock and USART - so it keeps
// counting down and will reset the whole MCU even if get_char_uart()'s
// software timeout above never fires for some reason (a hang somewhere
// else, a bug in the longjmp path, etc.). It's kicked once per command
// at the top of the main loop; if a command doesn't complete within the
// timeout, the board resets itself with no host/physical intervention
// needed at all.
static void iwdg_init(void) {
	IWDG->KR = 0x5555;   // unlock PR/RLR for writing
	IWDG->PR = 6;        // /256 prescaler: ~32kHz LSI / 256 = ~8ms per tick
	IWDG->RLR = 625;     // 625 * ~8ms = ~5s timeout - comfortably above both
	                     // the longest single command (Falcon sign ~170ms)
	                     // AND normal inter-command host-side gaps (capture
	                     // delays, retry/recovery sleeps), so it only fires
	                     // on a genuine hang, not a legitimate idle pause
	IWDG->KR = 0xCCCC;   // start the watchdog
}

//Local functions
void init();
void usart_init();
void oled_init();
void setBypass();
void setPLL();

const uint8_t glitched[] = { 0xFA, 0xCC };
const uint8_t cmdByteIsWrong[] = { 'B','a','d','C','m','d','\n',0x00};
const uint8_t codeVersion[] = { 'V','e','r',' ','4','.','0',0x00};

volatile uint8_t usbSerialEnabled=0;
volatile uint8_t clockspeed=168;
volatile uint8_t clockSource=0;

// Set GPIO Pin 2 to high.
#define BEGIN_INTERESTING_STUFF GPIOC->BSRRL = GPIO_Pin_2

// Set GPIO Pin 2 to low.
#define END_INTERESTING_STUFF GPIOC->BSRRH = GPIO_Pin_2

FalconState g_falcon;
void handle_falcon_decode_start() {
	BEGIN_INTERESTING_STUFF;
}
void handle_falcon_decode_finish() {
	END_INTERESTING_STUFF;
}

////////////////////////////////////////////////////
//MAIN FUNCTION: entry point for the board program//
////////////////////////////////////////////////////
int main(void) {
	uint8_t cmd;
	uint8_t tmp;

	PINATA_PATCH_falcon_set_decode_start_callback(&handle_falcon_decode_start);
	PINATA_PATCH_falcon_set_decode_finish_callback(&handle_falcon_decode_finish);

	//Set up the system clocks
	SystemInit();
	//Initialize peripherals and select IO interface
	init();

	iwdg_init();

	//Disable SysTick interrupt to avoid spikes every 1ms
	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;

	// If no jumper between PA9, VBUS
	if(!usbSerialEnabled) {
		// Enable USART3 in port gpioC (Pins PC10 TxD,PC11 RxD)
		usart_init();
	}

	// Optional peripherals: enable SPI and GPIO pins for OLED display
	oled_init();
	oled_clear();

	//////////////////////
	//MAIN FUNCTION LOOP//
	//////////////////////

	while (1) {
		// Landing point for a UART receive timeout (see get_char_uart()):
		// discard whatever command was in progress and go back to waiting
		// for a fresh command byte, instead of a dropped byte hanging the
		// board forever.
		setjmp(command_resync);
		// Every completed command (or resync) proves the board is alive -
		// kick the watchdog here, and only here, so a genuine mid-command
		// hang (stuck for the full ~2.5s timeout without getting back to
		// this point) triggers a full MCU reset instead of counting down
		// while the board is legitimately just waiting for the next byte.
		IWDG->KR = 0xAAAA;
		cmd=0;
		tmp=0;

		//Main processing section: select and execute cipher&mode
		get_char(&cmd);
		switch (cmd) {
			/////////Falcon (FN-DSA) commands/////////

			case CMD_SW_FALCON_SET_PUBLIC_AND_PRIVATE_KEY: {
				// Receive the input parameters and handle the request.
				get_bytes(FALCON_PUBLIC_KEY_SIZE, FalconState_getPublicKey(&g_falcon));
				get_bytes(FALCON_PRIVATE_KEY_SIZE, FalconState_getPrivateKey(&g_falcon));

				// Return the response.
				send_char(0);
				break;
			}

			case CMD_SW_FALCON_SIGN: {
				// Receive the input parameters.
				uint8_t* signedMessageBuffer = FalconState_getScratchPad(&g_falcon);
				get_bytes(FALCON_MESSAGE_SIZE, signedMessageBuffer + FALCON_SIGNATURE_SIZE);

				// Handle the request.
				// Note: GPIO Pin 2 is toggled inside FalconState_sign(), high from
				// the start of the secret-key f decode through the end of the full
				// signing computation.
				int result = FalconState_sign(&g_falcon, signedMessageBuffer, signedMessageBuffer + FALCON_SIGNATURE_SIZE);

				if (result == 0) {
					// OK: The message is now signed, let's send the signature of the message back.
					send_char(0);
					send_bytes(FALCON_SIGNATURE_SIZE, signedMessageBuffer);
				} else {
					// ERROR: Signing the message failed.
					send_char(1);
				}
				break;
			}

			case CMD_SW_FALCON_VERIFY: {
				// Receive the input parameters.
				uint8_t* signedMessageBuffer = FalconState_getScratchPad(&g_falcon);
				get_bytes(FALCON_SIGNED_MESSAGE_SIZE, signedMessageBuffer);

				// Handle the request.
				int result = FalconState_verify(&g_falcon, signedMessageBuffer, signedMessageBuffer + FALCON_SIGNATURE_SIZE);

				// Return the response.
				send_char(result == 0 ? 0 : 1);
				break;
			}

			case CMD_SW_FALCON_GET_KEY_SIZES: {
				const uint16_t publicKeySize = FALCON_PUBLIC_KEY_SIZE;
				const uint16_t privateKeySize = FALCON_PRIVATE_KEY_SIZE;
				// Send the response; MUST be in little-endian order!
				send_bytes(sizeof(publicKeySize), (const uint8_t*)&publicKeySize);
				send_bytes(sizeof(privateKeySize), (const uint8_t*)&privateKeySize);
				break;
			}

			//Code version command: returns code version string (8 bytes, "Ver x.x" ASCII encoded)
			case CMD_GET_CODE_REV:
				send_bytes(8, codeVersion);
				break;

			//Change clock speed on-the-fly and restart peripherals; predefined speeds are 16, 30, 84 and 168MHz. If parameter is not in this list, speed will be set to 168MHz by default.
			case CMD_CHANGE_CLK_SPEED:
				get_char(&tmp);
				setClockSpeed(tmp);
				send_char(clockspeed);
				break;

			//Change clock source to external. The argument specifies whether the clock is used directly (value = 0), or through the PLL (value != 0)
			case CMD_SET_EXTERNAL_CLOCK:
				get_char(&tmp);
				setExternalClock(tmp);
				send_char(clockSource);
				break;

			//Unknown command byte: return error
			default:
				send_bytes(8, cmdByteIsWrong);
				break;

		}
	}

	//If we glitch the board out of the main loop, it will end up here (target will loop forever sending bytes 0xFA, 0xCC)
	while (1) {
		send_bytes(2, glitched);
	}
	return 0;
}

////////////////////////////////////////////////////
//            END OF MAIN FUNCTION                //
////////////////////////////////////////////////////



///////////////////////////
//FUNCTION IMPLEMENTATION//
///////////////////////////

//init(): system initialization, pin configuration and system tick configuration for timers
void init() {
	/* STM32F4 GPIO ports */

	GPIO_InitTypeDef GPPortA,GPPortC,GPPortF, GPPortH;

	//PA9: IO configuration pin. Jumper between VBUS, PA9
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOA, ENABLE);
	GPPortA.GPIO_Pin =  GPIO_Pin_9;
	GPPortA.GPIO_Mode = GPIO_Mode_IN;
	GPPortA.GPIO_OType = GPIO_OType_PP;
	GPPortA.GPIO_Speed = GPIO_Speed_50MHz;
	GPPortA.GPIO_PuPd = GPIO_PuPd_DOWN;
	GPIO_Init(GPIOA, &GPPortA);

	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOF, ENABLE);
	GPPortF.GPIO_Pin = GPIO_Pin_2 | GPIO_Pin_4 | GPIO_Pin_5 | GPIO_Pin_6 | GPIO_Pin_8| GPIO_Pin_9;
	GPPortF.GPIO_Mode = GPIO_Mode_OUT;
	GPPortF.GPIO_OType = GPIO_OType_PP;
	GPPortF.GPIO_Speed = GPIO_Speed_100MHz;
	GPPortF.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOF, &GPPortF);

	//DEFAULT TRIGGER PIN IS PC2; utility functions defined in stm32f4xx_gpio.c in functions set_trigger() and clear_trigger() functions
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);
	GPPortC.GPIO_Pin = GPIO_Pin_1 | GPIO_Pin_2;
	GPPortC.GPIO_Mode = GPIO_Mode_OUT;
	GPPortC.GPIO_OType = GPIO_OType_PP;
	GPPortC.GPIO_Speed = GPIO_Speed_100MHz;
	GPPortC.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOC, &GPPortC);

	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOH, ENABLE);
	GPPortH.GPIO_Pin = GPIO_Pin_2 | GPIO_Pin_3;
	GPPortH.GPIO_Mode = GPIO_Mode_OUT;
	GPPortH.GPIO_OType = GPIO_OType_PP;
	GPPortH.GPIO_Speed = GPIO_Speed_100MHz;
	GPPortH.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOH, &GPPortH);
	/* Setup SysTick or crash */
	if (SysTick_Config(SystemCoreClock / 1000)) {
		CrashGracefully();
	}

	/* Setup USB virtual COM port if enabled; otherwise disable as it generates noise in the power lines */
	usbSerialEnabled = GPIO_ReadInputDataBit(GPIOA, GPIO_Pin_9);
	if (usbSerialEnabled) {
	USBD_Init(&USB_OTG_dev_main,
			USB_OTG_FS_CORE_ID,
			&USR_desc,
			&USBD_CDC_cb,
			&USR_cb);
	}

}

//usart_init: configures the usart3 interface
void usart_init(void) {
	/* USART3 configured as follows:
	 - BaudRate = 115200 baud
	 - Word Length = 8 Bits
	 - One Stop Bit
	 - No parity
	 - Hardware flow control disabled (RTS and CTS signals)
	 - Receive and transmit enabled
	 - PC10 TX pin, PC11 RX pin
	 */
	GPIO_InitTypeDef GPIO_InitStructure;
	USART_InitTypeDef USART_InitStructure;

	/* Enable GPIO clock */
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);

	/* Enable UART clock */
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, ENABLE);

	/* Connect PXx to USARTx_Tx*/
	GPIO_PinAFConfig(GPIOC, GPIO_PinSource10, GPIO_AF_USART3);

	/* Connect PXx to USARTx_Rx*/
	GPIO_PinAFConfig(GPIOC, GPIO_PinSource11, GPIO_AF_USART3);

	/* Configure USART Tx as alternate function  */
	GPIO_InitStructure.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_UP;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;

	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10;
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	GPIO_Init(GPIOC, &GPIO_InitStructure);

	/* Configure USART Rx as alternate function  */
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_11;
	GPIO_Init(GPIOC, &GPIO_InitStructure);

	USART_InitStructure.USART_BaudRate = 115200;
	USART_InitStructure.USART_WordLength = USART_WordLength_8b;
	USART_InitStructure.USART_StopBits = USART_StopBits_1;
	USART_InitStructure.USART_Parity = USART_Parity_No;
	USART_InitStructure.USART_HardwareFlowControl =
			USART_HardwareFlowControl_None;
	USART_InitStructure.USART_Mode = USART_Mode_Rx | USART_Mode_Tx;

	/* USART configuration */
	USART_Init(USART3, &USART_InitStructure);

	/* Enable USART */
	USART_Cmd(USART3, ENABLE);

}

//oled_init: configures the SPI2 interface with associated GPIO pins for SS, data/cmd# and reset lines
void oled_init(){
	/* Pins used by SPI2 & GPIOs for SSD1306 OLED display
	 * PB13 = SCK == blue wire to SSD1306 OLED display
	 * PB14 = MISO == nc
	 * PB15 = MOSI == green wire to SSD1306 OLED display
	 * PF4  = SS == white wire to SSD1306 OLED display
	 * PF5 = data/cmd# line of SSD1306 OLED display == yellow wire to SSD1306 OLED display
	 * PF8 = reset line of SSD1306 OLED display == orange wire to SSD1306 OLED display
	 *
	 */
	//Enable clock for GPIO pins for SPI
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOB, ENABLE);

	GPIO_InitTypeDef GPIO_InitStruct;
	GPIO_InitStruct.GPIO_Pin = GPIO_Pin_13 | GPIO_Pin_14|GPIO_Pin_15;
	GPIO_InitStruct.GPIO_Mode = GPIO_Mode_AF;
	GPIO_InitStruct.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStruct.GPIO_Speed = GPIO_Speed_100MHz;
	GPIO_InitStruct.GPIO_PuPd = GPIO_PuPd_UP;
	GPIO_Init(GPIOB, &GPIO_InitStruct);

	RCC_APB1PeriphClockCmd(RCC_APB1Periph_SPI2, ENABLE);
	SPI_InitTypeDef SPI_InitTypeDefStruct;

	SPI_InitTypeDefStruct.SPI_BaudRatePrescaler = SPI_BaudRatePrescaler_2; //APB1 bus speed=(168/4)=42MHz; SPI speed with prescaler 2-> (42/4)=21MHz
	SPI_InitTypeDefStruct.SPI_Direction = SPI_Direction_1Line_Tx;
	SPI_InitTypeDefStruct.SPI_Mode = SPI_Mode_Master;
	SPI_InitTypeDefStruct.SPI_DataSize = SPI_DataSize_8b;
	SPI_InitTypeDefStruct.SPI_NSS = SPI_NSS_Soft;
	SPI_InitTypeDefStruct.SPI_FirstBit = SPI_FirstBit_MSB;
	SPI_InitTypeDefStruct.SPI_CPOL = SPI_CPOL_Low;
	SPI_InitTypeDefStruct.SPI_CPHA = SPI_CPHA_1Edge;
	// connect SPI1 pins to SPI alternate function
	GPIO_PinAFConfig(GPIOB, GPIO_PinSource13 , GPIO_AF_SPI2);
	GPIO_PinAFConfig(GPIOB, GPIO_PinSource14, GPIO_AF_SPI2);
	GPIO_PinAFConfig(GPIOB, GPIO_PinSource15 , GPIO_AF_SPI2);
	SPI_Init(SPI2, &SPI_InitTypeDefStruct);
	SPI_Cmd(SPI2, ENABLE);

	//SPI interface and GPIO pins are configured: reset the OLED display
	oled_reset();
}

//////Interrupt Handlers/////////

void SysTick_Handler(void) {
	ticker++;
	if (downTicker > 0) {
		downTicker--;
	}
}
//Debugging: Hard error management
void HardFault_Handler(void) {CrashGracefully();}
void MemManage_Handler(void) {CrashGracefully();}
void BusFault_Handler(void) {CrashGracefully();}
void UsageFault_Handler(void) {CrashGracefully();}


////////I/O utility functions (UART, serial over USB)////////////

//System functions: disable/enable

//Wrapper functions for UART / serial over USB
//get_bytes: get an amount of nbytes bytes from IO interface into byte array ba
void get_bytes(uint32_t nbytes, uint8_t* ba) {
	if (usbSerialEnabled) {
		get_bytes_usb(nbytes,ba);
	} else {
		get_bytes_uart(nbytes,ba);
	}
}

//send_bytes: send an amount of nbytes bytes from byte array ba via IO interface
void send_bytes(uint32_t nbytes, const uint8_t *ba) {
	if (usbSerialEnabled) {
		send_bytes_usb(nbytes,ba);
	} else {
		send_bytes_uart(nbytes,ba);
	}
}

//get_char: receive a byte via IO interface
void get_char(uint8_t *ch) {
	if (usbSerialEnabled) {
		get_char_usb(ch);
	} else {
		get_char_uart(ch);
	}
}

// read_char: receive a byte via IO interface
uint8_t read_char() {
	uint8_t result;
	get_char(&result);
	return result;
}

//send_char: send a byte via IO interface
void send_char(uint8_t ch) {
	if (usbSerialEnabled) {
		send_char_usb(ch);
	} else {
		send_char_uart(ch);
	}
}

//UART IO
void get_char_uart(uint8_t *ch);

//get_bytes: get an amount of nbytes bytes from uart into byte array ba
void get_bytes_uart(uint32_t nbytes, uint8_t *ba) {
	int i;
	for (i = 0; i < nbytes; i++) {
		get_char_uart(&ba[i]);
	}
}
//send_bytes: send an amount of nbytes bytes from byte array ba via uart
void send_bytes_uart(uint32_t nbytes, const uint8_t *ba) {
	int i;
	for (i = 0; i < nbytes; i++) {
		while (!(USART3->SR & USART_SR_TXE));

		USART_SendData(USART3, ba[i]);
	}
}

//get_char: receive a byte via uart
//Bounded spin instead of an unconditional busy-wait: if a byte the host
//promised never shows up (dropped on the wire mid-command), bail back to
//the top of the main loop via command_resync rather than hanging forever.
//UART_RX_TIMEOUT_SPINS is a coarse iteration count, not a calibrated
//wall-clock timeout - it just needs to be generous enough to never fire
//during normal (even slow) host activity, and finite so a real dropped
//byte recovers in well under a second.
#define UART_RX_TIMEOUT_SPINS 500000UL
void get_char_uart(uint8_t *ch) {
	uint32_t spins = 0;
	while ((USART3->SR & USART_SR_RXNE) == 0) {
		if (++spins > UART_RX_TIMEOUT_SPINS) {
			longjmp(command_resync, 1);
		}
	}

	*ch = (uint8_t) USART_ReceiveData(USART3);
}

//send_char: send a byte via uart
void send_char_uart(uint8_t ch) {
	while (!(USART3->SR & USART_SR_TXE));

	USART_SendData(USART3, ch);
}

//Serial over USB communication functions
//get_bytes: get an amount of nbytes bytes into byte array ba via usb com port
void get_bytes_usb(uint32_t nbytes, uint8_t *ba) {
	int i;
	uint8_t tmp;
	for (i = 0; i < nbytes; i++) {
		tmp = 0;
		while (!VCP_get_char(&tmp));

		ba[i] = tmp;
	}
}
//send_bytes: send an amount of nbytes bytes from byte array ba via usb com port
void send_bytes_usb(uint32_t nbytes, const uint8_t *ba) {
	int i;
	for (i = 0; i < nbytes; i++) {
		VCP_put_char(ba[i]);
	}

}
//get_char: receive a byte over usb com port
void get_char_usb(uint8_t *ch) {
	uint8_t tmp=0;
	while (!VCP_get_char(&tmp));

	*ch = tmp;
}
//send_char: send a byte over usb com port
void send_char_usb(uint8_t ch) {
	VCP_put_char(ch);
}

//USB IRQ handlers
void OTG_FS_IRQHandler(void)
{
	if (usbSerialEnabled) {
		USBD_OTG_ISR_Handler (&USB_OTG_dev_main);
	}
}

void OTG_FS_WKUP_IRQHandler(void)
{
	if (usbSerialEnabled) {
		if (USB_OTG_dev_main.cfg.low_power) {
			*(uint32_t *)(0xE000ED10) &= 0xFFFFFFF9;
			SystemInit();
			USB_OTG_UngateClock(&USB_OTG_dev_main);
		}
		EXTI_ClearITPendingBit(EXTI_Line18);
	}
}

void CrashGracefully(void) {
	//Put anything you would like here to happen on a hard fault
	GPIOF->BSRRH = GPIO_Pin_6; //Example handler: PF6 enabled
}

/////Clock handling functions////////

//// Functions to change on-the-fly the clockspeed; supported speeds: 30, 84 and 168MHz ////
void setClockSpeed(uint8_t speed) {
	uint16_t timeout;

	// Enable HSI clock and switch to it while we mess with the PLLs
	RCC->CR |= RCC_CR_HSION;
	timeout = 0xFFFF;
	while (!(RCC->CR & RCC_CR_HSIRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_HSI;

	//Disable PLL, reconfigure settings, enable again PLL
	RCC->CR &= ~RCC_CR_PLLON;
	switch (speed) {	//PLLs config: HSE as ext. clk source, plls values for M,N,P,Q
		case 30:
			RCC_PLLConfig(RCC_PLLSource_HSE, 8, 240, 8, 5); clockspeed=30;
			break;
		case 84:
			RCC_PLLConfig(RCC_PLLSource_HSE, 8, 336, 4, 7); clockspeed=84;
			break;
		case 168:
		default: //If incorrect value, we also set speed to 168MHz and return that clockspeed is 168MHz
			RCC_PLLConfig(RCC_PLLSource_HSE, 8, 336, 2, 7);clockspeed=168;
			break;
	}
	RCC->CR |= RCC_CR_PLLON;

	//Wait for PLL and switch back to it
	timeout = 0xFFFF;
	while ((RCC->CR & RCC_CR_PLLRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_PLL;

	//Update system core clockspeed for peripherals to set configurations properly
	SystemCoreClockUpdate();

	//Reinitialize peripherals because changing the RCC_PLLConfig has messed up all the clocking
	init();
	if (!usbSerialEnabled) {
		usart_init();
	}

	clockSource = (RCC->CFGR & RCC_CFGR_SWS) >> 2;

	//Disable SysTick interrupt to avoid spikes every 1ms
	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
}

//switch clock to external clock supply
void setExternalClock(uint8_t source) {
	uint16_t timeout;

	// Enable HSI clock and switch to it while we mess with the PLLs
	RCC->CR |= RCC_CR_HSION;
	timeout = 0xFFFF;
	while (!(RCC->CR & RCC_CR_HSIRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_HSI;

	//Disable PLL and HSE
	RCC->CR &= ~RCC_CR_PLLON;
	RCC->CR &= ~RCC_CR_HSEON;

	setBypass();
	clockspeed = 8;
	if (source != 0) {
		setPLL();
		clockspeed = 168;
	}

	//Update system core clock speed for peripherals to set configurations properly
	SystemCoreClockUpdate();

	//Reinitialize peripherals because changing the clock source has messed up all the clocking
	init();
	if (!usbSerialEnabled) {
		usart_init();
	}

	clockSource = (RCC->CFGR & RCC_CFGR_SWS) >> 2;

	//Disable SysTick interrupt to avoid spikes every 1ms
	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
}


//Function to bypass the internal clock system with an external clock source
void setBypass() {
	uint16_t timeout;

	//Enable HSE bypass
	RCC->CR |= RCC_CR_HSEBYP;
	//Enable HSE
	RCC->CR |= RCC_CR_HSEON;

	//Wait for HSE and set it as the clock source
	timeout = 0xFFFF;
	while ((RCC->CR & RCC_CR_HSERDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_HSE;
}


//Function to reconfigure the internal PLLs
void setPLL() {
	uint16_t timeout;

	//disable PLL
	RCC->CR &= ~RCC_CR_PLLON;
	//reconfigure settings for 168 MHz
	RCC_PLLConfig(RCC_PLLSource_HSE, 8, 336, 2, 7);
	//re-enable PLL
	RCC->CR |= RCC_CR_PLLON;

	//Wait for PLL and set it as the clock source
	timeout = 0xFFFF;
	while ((RCC->CR & RCC_CR_PLLRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_PLL;
}
