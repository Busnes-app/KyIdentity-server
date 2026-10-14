import React, { useId, useLayoutEffect, useRef, useState } from 'react';

/**
 * A modal on native <dialog>: showModal() supplies the focus trap, inert page, Escape and
 * top-layer stacking, so a step-up prompt opened from another modal always lands on top.
 */
export function Modal({ title, onClose, className, closeOnBackdrop, returnFocus, children }: {
  title: React.ReactNode;
  onClose: () => void;
  className?: string;
  closeOnBackdrop?: boolean;
  /** Where focus goes on close, when the opener is no longer focused at mount. */
  returnFocus?: Element | null;
  children: React.ReactNode;
}) {
  const titleId = useId();
  const dialog = useRef<HTMLDialogElement>(null);
  // Children mount once the dialog is modal: until then the page's other modal makes it
  // inert, and an autoFocus child could not take focus.
  const [open, setOpen] = useState(false);
  useLayoutEffect(() => {
    const node = dialog.current;
    if (!node) return;
    const opener = returnFocus ?? document.activeElement;
    node.showModal();
    setOpen(true);
    return () => {
      node.close();
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
    };
  }, [returnFocus]);
  // React bubbles cancel from a nested dialog, so each modal answers only its own.
  return <dialog ref={dialog} className="modal-backdrop" aria-labelledby={titleId}
    onCancel={e => { if (e.target !== e.currentTarget) return; e.preventDefault(); onClose(); }}
    onMouseDown={closeOnBackdrop ? e => { if (e.target === e.currentTarget) onClose(); } : undefined}>
    <div className={className ? `modal-card ${className}` : 'modal-card'}>
      <div className="modal-header">
        <h3 id={titleId}>{title}</h3>
        <button type="button" className="close-btn" onClick={onClose} aria-label="Close">×</button>
      </div>
      {open && children}
    </div>
  </dialog>;
}
