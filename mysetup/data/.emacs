
(defalias 'yes-or-no-p 'y-or-n-p)

(global-set-key (kbd "<f1>") 'delete-other-windows)
(global-set-key (kbd "<f2>") 'split-window)
(global-set-key (kbd "<f4>") 'other-window)
(global-set-key (kbd "<f5>") 'comment-region)
(global-set-key (kbd "<S-f5>") 'uncomment-region)
(global-set-key (kbd "<f7>") 'indent-region)
(global-set-key (kbd "<f9>") 'recompile)
;(global-set-key (kbd "<f9>") 'recompile-noask)
(global-set-key (kbd "<S-f9>") 'compile)
(global-set-key (kbd "<f8>") 'kill-compilation)
(global-set-key (kbd "<f10>") 'next-error)
(global-set-key (kbd "<S-f10>") 'previous-error)
(global-set-key (kbd "<f11>") 'kill-all-dired-buffers)
(global-set-key (kbd "<S-f11>") 'kill-some-buffers)
(global-set-key (kbd "<f12>") 'electric-buffer-list)

(custom-set-variables
  ;; custom-set-variables was added by Custom.
  ;; If you edit it by hand, you could mess it up, so be careful.
  ;; Your init file should contain only one such instance.
  ;; If there is more than one, they won't work right.
 '(Man-notify-method (quote aggressive))
 '(column-number-mode t)
 '(compilation-ask-about-save nil)
 '(compile-command "gmb ")
 '(delete-old-versions t)
 '(dired-auto-revert-buffer (quote dired-directory-changed-p))
 '(dired-kept-versions 2)
 '(global-auto-revert-mode t)
 '(indent-tabs-mode nil)
 '(inhibit-startup-screen t)
 '(kept-new-versions 2)
 '(kept-old-versions 0)
 '(pc-selection-mode t)
 '(rst-level-face-base-color "black")
 '(safe-local-variable-values (quote ((encoding . utf-8))))
 '(save-place t nil (saveplace))
 '(savehist-mode t nil (savehist))
 '(show-paren-mode t)
 '(show-paren-ring-bell-on-mismatch t)
 '(show-paren-style (quote mixed))
 '(tab-width 4)
 '(tool-bar-mode nil)
 '(vc-make-backup-files nil)
 '(version-control t))
(custom-set-faces
  ;; custom-set-faces was added by Custom.
  ;; If you edit it by hand, you could mess it up, so be careful.
  ;; Your init file should contain only one such instance.
  ;; If there is more than one, they won't work right.
 '(default ((t (:inherit nil :stipple nil :background "#000000" :foreground "Wheat" :inverse-video nil :box nil :strike-through nil :overline nil :underline nil :slant normal :weight normal :height 98 :width normal :foundry "unknown" :family "Droid Sans Mono")))))


;;;;;;;;;;;;;;

;;; midnight mode

(require 'midnight)

;;kill buffers if they were last disabled more than this seconds ago
(setq clean-buffer-list-delay-special 3600)

(defvar clean-buffer-list-timer nil
  "Stores clean-buffer-list timer if there is one. You can disable clean-buffer-list by (cancel-timer clean-buffer-list-timer).")

;; run clean-buffer-list every 2 hours
(setq clean-buffer-list-timer (run-at-time t 900 'clean-buffer-list))

;; kill everything, clean-buffer-list is very intelligent at not killing
;; unsaved buffer.
(setq clean-buffer-list-kill-regexps '("^.*$"))

;; keep these buffer untouched
;; prevent append multiple times
(defvar clean-buffer-list-kill-never-buffer-names-init
  clean-buffer-list-kill-never-buffer-names
  "Init value for clean-buffer-list-kill-never-buffer-names")
(setq clean-buffer-list-kill-never-buffer-names
      (append
       '("*Messages*" "*cmd*" "*scratch*" "*w3m*" "*w3m-cache*" "*Inferior Octave*")
       clean-buffer-list-kill-never-buffer-names-init))

;; prevent append multiple times
(defvar clean-buffer-list-kill-never-regexps-init
  clean-buffer-list-kill-never-regexps
  "Init value for clean-buffer-list-kill-never-regexps")
;; append to *-init instead of itself
(setq clean-buffer-list-kill-never-regexps
      (append '("^\\*EMMS Playlist\\*.*$")
	      clean-buffer-list-kill-never-regexps-init))


;;;;;;

(defun kill-all-dired-buffers ()
  "Kill all dired buffers."
  (interactive)
  (save-excursion
	(let ((count 0))
	  (dolist (buffer (buffer-list))
		(set-buffer buffer)
		(when (equal major-mode 'dired-mode)
		  (setq count (1+ count))
		  (kill-buffer buffer)))
	  (message "Killed %i dired buffer(s)." count))))
