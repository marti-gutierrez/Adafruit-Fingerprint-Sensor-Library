/*!
 * @file Adafruit_Fingerprint.cpp
 *
 * @mainpage Adafruit Fingerprint Sensor Library
 *
 * @section intro_sec Introduction
 *
 * This is a library for our optical Fingerprint sensor
 *
 * Designed specifically to work with the Adafruit Fingerprint sensor
 * ----> http://www.adafruit.com/products/751
 *
 * These displays use TTL Serial to communicate, 2 pins are required to
 * interface
 * Adafruit invests time and resources providing this open source code,
 * please support Adafruit and open-source hardware by purchasing
 * products from Adafruit!
 *
 * @section author Author
 *
 * Written by Limor Fried/Ladyada for Adafruit Industries.
 *
 * @section license License
 *
 * BSD license, all text above must be included in any redistribution
 *
 */

#include "Adafruit_Fingerprint.h"
#include <stdarg.h>

typedef struct
{
  uint8_t address[4]; ///< 32-bit Fingerprint sensor address
  uint8_t type;       ///< Type of packet
  uint16_t length;    ///< Length of packet
  uint8_t data[64];   ///< The raw buffer for packet payload
} s_Adafruit_Fingerprint_Packet;

s_Adafruit_Fingerprint_Packet packet;
uint32_t password = 0x00000000;

static void GET_CMD_PACKET(uint8_t no_params, ...)
{
  va_list args;
  va_start(args, no_params);
  for (uint8_t i = 0; i < no_params; i++)
  {
    packet.data[i] = va_arg(args, int);
  }
  va_end(args);
  packet.type = FINGERPRINT_COMMANDPACKET;
  packet.length = no_params;
  writeStructuredPacket();
  if (getStructuredPacket() != FINGERPRINT_OK)
    return FINGERPRINT_PACKETRECIEVEERR;
  if (packet.type != FINGERPRINT_ACKPACKET)
    return FINGERPRINT_PACKETRECIEVEERR;
}

/**************************************************************************/
/*!
    @brief  Verifies the sensors' access password (default password is
   0x0000000). A good way to also check if the sensors is active and responding
    @returns True if password is correct
*/
/**************************************************************************/

static uint8_t checkPassword()
{
  GET_CMD_PACKET(5, FINGERPRINT_VERIFYPASSWORD, (uint8_t)(password >> 24),
                 (uint8_t)(password >> 16), (uint8_t)(password >> 8),
                 (uint8_t)(password & 0xFF));
  return (packet.data[0] == FINGERPRINT_OK) ? FINGERPRINT_OK : FINGERPRINT_PACKETRECIEVEERR;
}

bool verifyPassword()
{
  return checkPassword() == FINGERPRINT_OK;
}

/**************************************************************************/
/*!
    @brief  Get the sensors parameters, fills in the member variables
    status_reg, system_id, capacity, security_level, device_addr, packet_len
    and baud_rate
    @returns True if password is correct
*/
/**************************************************************************/
uint8_t getParameters(s_Adafruit_Fingerprint *fingerprint)
{
  GET_CMD_PACKET(1, FINGERPRINT_READSYSPARAM);

  fingerprint->status_reg = ((uint16_t)packet.data[1] << 8) | packet.data[2];
  fingerprint->system_id = ((uint16_t)packet.data[3] << 8) | packet.data[4];
  fingerprint->capacity = ((uint16_t)packet.data[5] << 8) | packet.data[6];
  fingerprint->security_leve = ((uint16_t)packet.data[7] << 8) | packet.data[8];
  fingerprint->device_addr = ((uint32_t)packet.data[9] << 24) |
                             ((uint32_t)packet.data[10] << 16) |
                             ((uint32_t)packet.data[11] << 8) | (uint32_t)packet.data[12];
  uint8_t packet_len = ((uint16_t)packet.data[13] << 8) | packet.data[14];

  const uint8_t idx_len[4] = {32, 64, 128, 256};
  fingerprint->packet_len = idx_len[packet_len];
  fingerprint->baud_rate = (((uint16_t)packet.data[15] << 8) | packet.data[16]) * 9600;

  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Ask the sensor to take an image of the finger pressed on surface
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_NOFINGER</code> if no finger detected
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
    @returns <code>FINGERPRINT_IMAGEFAIL</code> on imaging error
*/
/**************************************************************************/
uint8_t getImage()
{
  GET_CMD_PACKET(1, FINGERPRINT_GETIMAGE);
  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Ask the sensor to convert image to feature template
    @param slot Location to place feature template (put one in 1 and another in
   2 for verification to create model)
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_IMAGEMESS</code> if image is too messy
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
    @returns <code>FINGERPRINT_FEATUREFAIL</code> on failure to identify
   fingerprint features
    @returns <code>FINGERPRINT_INVALIDIMAGE</code> on failure to identify
   fingerprint features
*/
uint8_t image2Tz(uint8_t slot)
{
  GET_CMD_PACKET(2, FINGERPRINT_IMAGE2TZ, slot);
  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Ask the sensor to take two print feature template and create a
   model
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
    @returns <code>FINGERPRINT_ENROLLMISMATCH</code> on mismatch of fingerprints
*/
uint8_t createModel()
{
  GET_CMD_PACKET(1, FINGERPRINT_REGMODEL);
  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Ask the sensor to store the calculated model for later matching
    @param   location The model location #
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_BADLOCATION</code> if the location is invalid
    @returns <code>FINGERPRINT_FLASHERR</code> if the model couldn't be written
   to flash memory
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
uint8_t storeModel(uint16_t location)
{
  GET_CMD_PACKET(4, FINGERPRINT_STORE, 0x01, (uint8_t)(location >> 8),
                 (uint8_t)(location & 0xFF));
  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Ask the sensor to load a fingerprint model from flash into buffer 1
    @param   location The model location #
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_BADLOCATION</code> if the location is invalid
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
/* uint8_t Adafruit_Fingerprint::loadModel(uint16_t location)
{
  SEND_CMD_PACKET(FINGERPRINT_LOAD, 0x01, (uint8_t)(location >> 8),
                  (uint8_t)(location & 0xFF));
} */

/**************************************************************************/
/*!
    @brief   Ask the sensor to transfer 256-byte fingerprint template from the
   buffer to the UART
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
/* uint8_t Adafruit_Fingerprint::getModel(void)
{
  SEND_CMD_PACKET(FINGERPRINT_UPLOAD, 0x01);
} */

/**************************************************************************/
/*!
    @brief   Ask the sensor to delete a model in memory
    @param   location The model location #
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_BADLOCATION</code> if the location is invalid
    @returns <code>FINGERPRINT_FLASHERR</code> if the model couldn't be written
   to flash memory
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
uint8_t deleteModel(uint16_t location)
{
  GET_CMD_PACKET(5, FINGERPRINT_DELETE, (uint8_t)(location >> 8),
                 (uint8_t)(location & 0xFF), 0x00, 0x01);
  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Ask the sensor to delete ALL models in memory
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_BADLOCATION</code> if the location is invalid
    @returns <code>FINGERPRINT_FLASHERR</code> if the model couldn't be written
   to flash memory
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
uint8_t emptyDatabase()
{
  GET_CMD_PACKET(1, FINGERPRINT_EMPTY);
  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Ask the sensor to search the current slot 1 fingerprint features to
   match saved templates. The matching location is stored in <b>fingerID</b> and
   the matching confidence in <b>confidence</b>
    @returns <code>FINGERPRINT_OK</code> on fingerprint match success
    @returns <code>FINGERPRINT_NOTFOUND</code> no match made
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
/**************************************************************************/
/* uint8_t Adafruit_Fingerprint::fingerFastSearch(void)
{
  // high speed search of slot #1 starting at page 0x0000 and page #0x00A3
  GET_CMD_PACKET(FINGERPRINT_HISPEEDSEARCH, 0x01, 0x00, 0x00, 0x00, 0xA3);
  fingerID = 0xFFFF;
  confidence = 0xFFFF;

  fingerID = packet.data[1];
  fingerID <<= 8;
  fingerID |= packet.data[2];

  confidence = packet.data[3];
  confidence <<= 8;
  confidence |= packet.data[4];

  return packet.data[0];
} */

/**************************************************************************/
/*!
    @brief   Control the built in LED
    @param on True if you want LED on, False to turn LED off
    @returns <code>FINGERPRINT_OK</code> on success
*/
/**************************************************************************/
uint8_t LEDcontrol(bool state)
{
  uint8_t instruction = (state) ? FINGERPRINT_LEDON : FINGERPRINT_LEDOFF;
  GET_CMD_PACKET(5, instruction, 0x00, 0x00, 0x00, 0x00);
  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Control the built in Aura LED (if exists). Check datasheet/manual
    for different colors and control codes available
    @param control The control code (e.g. breathing, full on)
    @param speed How fast to go through the breathing/blinking cycles
    @param coloridx What color to light the indicator
    @param count How many repeats of blinks/breathing cycles
    @returns <code>FINGERPRINT_OK</code> on fingerprint match success
    @returns <code>FINGERPRINT_NOTFOUND</code> no match made
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
/**************************************************************************/
/* uint8_t Adafruit_Fingerprint::LEDcontrol(uint8_t control, uint8_t speed,
                                         uint8_t coloridx, uint8_t count)
{
  SEND_CMD_PACKET(FINGERPRINT_AURALEDCONFIG, control, speed, coloridx, count);
} */

/**************************************************************************/
/*!
    @brief   Ask the sensor to search the current slot fingerprint features to
   match saved templates. The matching location is stored in <b>fingerID</b> and
   the matching confidence in <b>confidence</b>
   @param slot The slot to use for the print search, defaults to 1
    @returns <code>FINGERPRINT_OK</code> on fingerprint match success
    @returns <code>FINGERPRINT_NOTFOUND</code> no match made
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
/**************************************************************************/
uint8_t fingerSearch(s_Adafruit_Fingerprint *fingerprint, uint8_t slot)
{
  // search of slot starting thru the capacity
  GET_CMD_PACKET(FINGERPRINT_SEARCH, slot, 0x00, 0x00, (uint8_t)(fingerprint->capacity >> 8),
                 (uint8_t)(fingerprint->capacity & 0xFF));

  fingerprint->fingerID = (packet.data[1] << 8 | packet.data[2]);
  fingerprint->confidence = (packet.data[3] << 8 | packet.data[4]);

  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Ask the sensor for the number of templates stored in memory. The
   number is stored in <b>templateCount</b> on success.
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
/**************************************************************************/
uint8_t getTemplateCount(s_Adafruit_Fingerprint *fingerprint)
{
  GET_CMD_PACKET(1, FINGERPRINT_TEMPLATECOUNT);

  fingerprint->templateCount = (packet.data[1] << 8 | packet.data[2]);
  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Set the password on the sensor (future communication will require
   password verification so don't forget it!!!)
    @param   password 32-bit password code
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_PACKETRECIEVEERR</code> on communication error
*/
/**************************************************************************/
uint8_t setPassword(uint32_t newPassword)
{
  password = newPassword;
  GET_CMD_PACKET(5, FINGERPRINT_SETPASSWORD, (uint8_t)(password >> 24),
                 (uint8_t)(password >> 16), (uint8_t)(password >> 8),
                 (uint8_t)(password & 0xFF));
  return packet.data[0];
}

/**************************************************************************/
/*!
    @brief   Helper function to process a packet and send it over UART to the
   sensor
    @param   packet A structure containing the bytes to transmit
*/
/**************************************************************************/

void writeStructuredPacket(void (*write)(uint8_t))
{

  (*write)((uint8_t)(FINGERPRINT_STARTCODE >> 8));
  (*write)((uint8_t)(FINGERPRINT_STARTCODE & 0xFF));
  (*write)(0xFF);
  (*write)(0xFF);
  (*write)(0xFF);
  (*write)(0xFF);
  (*write)(packet.type);

  uint16_t wire_length = packet.length + 2;
  (*write)((uint8_t)(wire_length >> 8));
  (*write)((uint8_t)(wire_length & 0xFF));

  uint16_t sum = ((wire_length) >> 8) + ((wire_length)&0xFF) + packet.type;
  for (uint8_t i = 0; i < packet.length; i++)
  {
    (*write)(packet.data[i]);
    sum += packet.data[i];
  }

  (*write)((uint8_t)(sum >> 8));
  (*write)((uint8_t)(sum & 0xFF));
}

/**************************************************************************/
/*!
    @brief   Helper function to receive data over UART from the sensor and
   process it into a packet
    @param   packet A structure containing the bytes received
    @param   timeout how many milliseconds we're willing to wait
    @returns <code>FINGERPRINT_OK</code> on success
    @returns <code>FINGERPRINT_TIMEOUT</code> or
   <code>FINGERPRINT_BADPACKET</code> on failure
*/
/**************************************************************************/
uint8_t getStructuredPacket(uint16_t timeout, uint8_t (*read)(void))
{
  uint8_t byte;
  const uint8_t header[7] = {(FINGERPRINT_STARTCODE >> 8), (FINGERPRINT_STARTCODE & 0xFF), 0xFF, 0xFF, 0xFF, 0xFF, FINGERPRINT_ACKPACKET};
  uint16_t idx = 0, timer = 0;

  while (1) // loop
  {
    /* while (!mySerial->available())
    {
      delay(1);
      timer++;
      if (timer >= timeout)
      {
        return FINGERPRINT_TIMEOUT;
      }
    } */
    byte = (*read)();
    if (idx <= 6)
    {
      if (byte != header[idx])
        return FINGERPRINT_BADPACKET;
    }
    if (idx == 8)
      packet.length = byte;
    if (idx > 8)
    {
      packet.data[idx - 9] = byte;
      if ((idx - 8) == packet.length)
        return FINGERPRINT_OK;
    }
    idx++;
    if ((idx + 9) >= sizeof(packet.data))
    {
      return FINGERPRINT_BADPACKET;
    }
  }
  // Shouldn't get here so...
  return FINGERPRINT_BADPACKET;
}
