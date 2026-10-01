import Java from 'frida-java-bridge';

// If no PoR arrives within this many ms after an injection, advance anyway.
const POR_TIMEOUT_MS = 5000;

let onPorReceived = null;

rpc.exports = {
  inject: function (pdusHex, slot) {
    Java.perform(function () {
      runInjection(pdusHex, slot);
    });
  }
};

function hexToByteArray(hex) {
  const out = [];
  for (let i = 0; i < hex.length; i += 2) {
    // Java bytes are signed; values >= 0x80 must be sent as negative numbers.
    out.push((parseInt(hex.substr(i, 2), 16) << 24) >> 24);
  }
  return Java.array('byte', out);
}

function runInjection(pdusHex, slot) {
  const IccIoResult = Java.use('com.android.internal.telephony.uicc.IccIoResult');
  const IccIoInit = IccIoResult.$init.overload('int', 'int', '[B');

  IccIoInit.implementation = function (sw1, sw2, payload) {
    this.$init(sw1, sw2, payload);
    if (payload) {
      const hex = Array.from(payload)
        .map(b => (b & 0xff).toString(16).padStart(2, '0'))
        .join('');
      send({ type: 'por', sw1: sw1 & 0xff, sw2: sw2 & 0xff, hex: hex });
    }
    if (onPorReceived) {
      onPorReceived();
    }
  };

  const PhoneFactory = Java.use('com.android.internal.telephony.PhoneFactory');
  const SmsMessage = Java.use('android.telephony.SmsMessage');

  const phone = PhoneFactory.getPhone(slot);
  if (!phone) {
    send({ type: 'error', message: 'No Phone instance for slot ' + slot });
    return;
  }
  send({ type: 'log', message: 'Phone slot ' + phone.getPhoneId() + ', subId ' + phone.getSubId() });

  let targetController;
  try {
    targetController = phone.getSmsDispatchersController();
  } catch (e) {
    send({
      type: 'error', message: 'getSmsDispatchersController() threw: ' + e +
        ' (method may differ on this Android version)'
    });
    return;
  }
  if (!targetController) {
    send({ type: 'error', message: 'Could not retrieve SmsDispatchersController for slot ' + slot });
    return;
  }

  const format = '3gpp';
  const createFromPdu = SmsMessage.createFromPdu.overload('[B', 'java.lang.String');
  const injectMethod = targetController.injectSmsPdu.overload(
    'android.telephony.SmsMessage',
    'java.lang.String',
    'com.android.internal.telephony.SmsDispatchersController$SmsInjectionCallback',
    'boolean',
    'boolean',
    'int'
  );

  const CallbackIface = Java.use(
    'com.android.internal.telephony.SmsDispatchersController$SmsInjectionCallback'
  );
  const InjectionCallback = Java.registerClass({
    name: 'com.frida.SmsInjectionCallbackImpl',
    implements: [CallbackIface],
    methods: {
      onSmsInjectedResult: [{
        returnType: 'void',
        argumentTypes: ['int'],
        implementation: function (result) {
          send({ type: 'log', message: 'onSmsInjectedResult(result=' + result + ')' });
        }
      }]
    }
  });
  const cb = InjectionCallback.$new();

  let currentIndex = 0;
  let pendingTimer = null;

  function finish() {
    if (pendingTimer !== null) {
      clearTimeout(pendingTimer);
      pendingTimer = null;
    }
    onPorReceived = null;
    IccIoInit.implementation = null;
    send({ type: 'done', count: pdusHex.length });
  }

  function injectNext() {
    if (pendingTimer !== null) {
      clearTimeout(pendingTimer);
      pendingTimer = null;
    }
    if (currentIndex >= pdusHex.length) {
      finish();
      return;
    }

    const idx = currentIndex;
    currentIndex++;
    send({ type: 'inject', index: idx, total: pdusHex.length });

    Java.perform(function () {
      const msg = createFromPdu.call(SmsMessage, hexToByteArray(pdusHex[idx]), format);
      // injectSmsPdu(msg, format, callback, ignoreClass, isOverIms, token)
      injectMethod.call(targetController, msg, format, cb, true, false, 0);
    });

    pendingTimer = setTimeout(function () {
      pendingTimer = null;
      send({ type: 'timeout', index: idx });
      injectNext();
    }, POR_TIMEOUT_MS);
  }

  onPorReceived = injectNext;
  send({ type: 'log', message: 'Starting injection of ' + pdusHex.length + ' PDU(s)' });
  injectNext();
}
