/**
 * A simple LTI PostMessage client for communicating with an LTI platform.
 * @see https://www.imsglobal.org/spec/lti-pm-s/v0p1
 */
class LtiPostMessageClient {
    /**
     * Construct a new LtiPostMessageClient.
     * @param targetOrigin The target origin to send messages to.
     * @param timeout The default timeout for responses in milliseconds.
     */
    constructor({targetOrigin = '*', timeout = 5000} = {}) {
        this.targetOrigin = targetOrigin;
        this.timeout = timeout;
    }

    /**
     * Attempt to generate a UUID and falls back to a random string.
     * @returns {string}
     */
    uuid() {
        if (self.crypto && self.crypto.randomUUID) {
            return self.crypto.randomUUID();
        } else {
            // IE 11 Doesn't have randomUUID so fall back to short random string.
            return (Math.random() + 1).toString(36).substring(2, 5)
        }
    }

    getTarget() {
        let target;
        if (window.parent === window) {
            // We're not in an iframe so must have been opened by the platform
            target = window.opener;
        }  else {
            // We're in an iframe so the platform is our parent
            if (window.parent) {
                target = window.parent;
            }
        }
        return target
    }

    /**
     * Enable or disable debug logging of all sent and received postMessages.
     * @param enable If true enable some debug logging to the browser console.
     */
    debug(enable) {
        if (enable && !this.debugHandler) {
            this.debugHandler = (event) => {
                console.debug('Received message:', event)
            }
            window.addEventListener('message', this.debugHandler);
        } else {
            if (this.debugHandler) {
                window.removeEventListener('message', this.debugHandler)
            }
        }
    }

    postMessage(message) {
        const origin = this.targetOrigin;
        let responseHandler
        let timeoutId;
        const target = this.getTarget()
        return new Promise((resolve, reject) => {
            responseHandler = (event) => {
                // This isn't a message we're expecting
                if (typeof event.data !== "object") {
                    return;
                }
                // Validate it's the response type you expect
                if (event.data.subject !== message.subject + ".response") {
                    return;
                }
                // Validate the message id matches the id you sent
                if (event.data.message_id !== message.message_id) {
                    return;
                }
                // Validate that the event's origin is the same as the derived platform origin
                if (origin !== '*' && event.origin !== origin) {
                    return;
                }
                // handle errors
                if (event.data.error) {
                    // handle errors (message and code)
                    reject(new Error('Postmessage failure: '+event.data.error.code+' - '+event.data.error.message));
                } else {
                    resolve(event)
                }
            }

            try {
                window.addEventListener('message', responseHandler);
                timeoutId = window.setTimeout(() => reject(new Error('timeout')), this.timeout);
                if (this.debugHandler) {
                    console.debug('Sending message:', message)
                }
                target.postMessage(message, this.targetOrigin);
            } catch (error) {
                reject(error);
            }
        }).finally(() => {
            window.removeEventListener('message', responseHandler)
            window.clearTimeout(timeoutId);
        })
    }

    /**
     * Store some data using LTI storage.
     * @param key The key to store the data against.
     * @param value The value to store.
     * @returns {Promise<void>} A promise that resolves when the data is successfully stored (we've had confirmation).
     */
    async setData(key, value) {
        const id = this.uuid()
        const message = {
            subject: 'lti.put_data',
            key: key,
            value: value,
            message_id: id
        }
        return this.postMessage(message);
    }

    /**
     * Retrieve some data using LTI storage.
     * @param key The key to retrieve the data for.
     * @returns {Promise<{value: *, event: *}>} A promise that resolves with an object containing the value and the original event.
     */
    async getData(key) {
        const id = this.uuid()
        const message = {
            subject: 'lti.get_data',
            key: key,
            message_id: id
        }
        return this.postMessage(message)
            .then((event => ({value: event.data.value, event})))
    }
}