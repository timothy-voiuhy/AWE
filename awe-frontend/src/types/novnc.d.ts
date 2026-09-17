declare module '@novnc/novnc' {
  export default class RFB {
    constructor(target: HTMLElement, url: string, options?: Record<string, unknown>)
    scaleViewport: boolean
    resizeSession: boolean
    viewOnly: boolean
    addEventListener(type: string, listener: (event: Event) => void): void
    disconnect(): void
  }
}
