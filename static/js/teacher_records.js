// Wait for DOM ready
$(document).ready(function() {
  $('.toggleEditRoomBtn').click(function() {
    const roomId = $(this).data('room-id');
    $('#editRoomForm-' + roomId).toggle();
  });

  $('.cancelEditRoomBtn').click(function() {
    const roomId = $(this).data('room-id');
    $('#editRoomForm-' + roomId).hide();
  });
  // Toggle Schedule Form
  $('#toggleScheduleForm').click(function() {
    $('#scheduleForm').toggle();
    $('#addRoomForm').hide();
  });

  // Toggle Add Room Form
  $('#toggleAddRoomForm').click(function() {
    $('#addRoomForm').toggle();
    $('#scheduleForm').hide();
  });

  // Initialize Select2 for multiselect fields
  $('#invited_users').select2({
    width: '100%'
  });

  // Show inline edit meeting form
  $('.toggleEditMeetingBtn').click(function() {
    const meetingId = $(this).data('meeting-id');
    $('#editMeetingForm-' + meetingId).toggle();
  });

  // Cancel edit meeting form
  $('.cancelEditMeetingBtn').click(function() {
    const meetingId = $(this).data('meeting-id');
    $('#editMeetingForm-' + meetingId).hide();
  });
});