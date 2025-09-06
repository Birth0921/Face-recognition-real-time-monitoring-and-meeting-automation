document.addEventListener('DOMContentLoaded', () => {
  // Auto open modal if ?edit=email@domain.com is in URL
  const urlParams = new URLSearchParams(window.location.search);
  const editEmail = urlParams.get('edit');
  if (editEmail) {
    const safeId = editEmail.replace(/[@.]/g, '_');
    const modalEl = document.getElementById(`editUserModal-${safeId}`);
    if (modalEl) {
      const modal = new bootstrap.Modal(modalEl);
      modal.show();
    }
  }

  // Delete user form handler
  const deleteForm = document.getElementById('deleteUserForm');
  if (deleteForm) {
    deleteForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = e.target.email.value.trim();
      if (!email) {
        Swal.fire("Error", "Please enter a valid email.", "error");
        return;
      }

      const result = await Swal.fire({
        title: 'Confirm Delete',
        text: `Are you sure you want to delete the student with email: ${email}?`,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Yes, delete',
      });

      if (result.isConfirmed) {
        try {
          const response = await fetch('/delete_user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
          });
          const data = await response.json();
          if (response.ok && data.status === 'success') {
            Swal.fire('Deleted!', data.message, 'success').then(() => {
              if (data.logout) {
                window.location.href = '/login';  // match Flask redirect route
              } else {
                window.location.reload();
              }
            });
          } else {
            Swal.fire('Error', data.message || 'Failed to delete user.', 'error');
          }
        } catch (error) {
          Swal.fire('Error', 'An unexpected error occurred.', 'error');
        }
      }
    });
  }

  // Edit user forms handler
  document.querySelectorAll("form[id^='editUserForm-']").forEach((form) => {
    form.addEventListener("submit", function (e) {
      e.preventDefault();

      Swal.fire({
        title: "Confirm Edit",
        text: "Are you sure you want to save changes?",
        icon: "question",
        showCancelButton: true,
        confirmButtonText: "Yes, save",
        cancelButtonText: "Cancel"
      }).then((result) => {
        if (result.isConfirmed) {
          fetch(form.action, {
            method: "POST",
            body: new FormData(form)
          })
          .then(async (response) => {
            let data;
            try {
              data = await response.json();
            } catch {
              data = null;
            }

            if (response.ok && data?.status === 'success') {
              Swal.fire({
                title: "Updated!",
                text: data.message || "User details updated successfully.",
                icon: "success",
                timer: 1500,
                showConfirmButton: false
              }).then(() => {
                window.location.reload();
              });
            } else {
              Swal.fire("Error", data?.message || "Something went wrong.", "error");
            }
          })
          .catch(() => {
            Swal.fire("Error", "Request failed. Check connection.", "error");
          });
        }
      });
    });
  });

});
